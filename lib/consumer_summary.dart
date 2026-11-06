import 'package:flutter/material.dart';

import 'core/ack_store.dart';
import 'core/event.dart';
import 'core/pii_detector.dart';
import 'impact.dart';
import 'protection_banner.dart';
import 'reasoning.dart';

enum SafetyLevel { safe, warning, alert }

enum Confidence { high, medium, low }

enum OverallStatus {
  strong('Strong Protection', Colors.green),
  good('Good Protection', Colors.lightGreen),
  moderate('Moderate Exposure', Colors.amber),
  high('High Exposure', Colors.deepOrange),
  urgent('Urgent Attention Required', Colors.red);

  const OverallStatus(this.label, this.color);
  final String label;
  final Color color;

  static OverallStatus fromScore(int s) =>
      s >= 91 ? strong : s >= 76 ? good : s >= 51 ? moderate : s >= 26 ? high : urgent;
}

/// One row of "Sensitive information": a plain-language kind of data and what happened to it.
class SensitiveItem {
  SensitiveItem(this.title, this.icon, this.level, this.detail, this.confidence);
  final String title;
  final IconData icon;
  final SafetyLevel level;
  final String detail;
  final int? confidence; // percent; null when nothing was detected
}

class TrackingSummary {
  int trackers = 0, telemetry = 0, advertising = 0; // blocked
  int trackersSeen = 0, telemetrySeen = 0, advertisingSeen = 0;
}

enum Risk {
  safe('Safe', Colors.green),
  low('Low', Colors.lightGreen),
  medium('Medium', Colors.amber),
  high('High', Colors.deepOrange),
  critical('Critical', Colors.red);

  const Risk(this.label, this.color);
  final String label;
  final Color color;
}

class ConsumerSummary {
  ConsumerSummary._(this.score, this.status, this.items, this.tracking, this.trend, this.headline,
      this.details, this.actions, this.blockedTotal, this.leftTotal, this.reasonings, this.impact, this.risk, this.assessment, this.scoreDelta, this.trackerHosts, this.newTrackers);

  final int? scoreDelta; // change since the last scan, null if there is no earlier scan
  final int trackerHosts; // trackers identified (detection visibility, not a penalty)
  final int newTrackers; // trackers not seen in the previous scan

  String get scoreChangeText => scoreDelta == null ? 'First scan' : scoreDelta! > 0 ? '+$scoreDelta' : scoreDelta! < 0 ? '$scoreDelta' : 'No change';
  String get exposureTrend => scoreDelta == null ? 'Baseline set' : scoreDelta! > 0 ? 'Improving ↑' : scoreDelta! < 0 ? 'Worsening ↓' : 'Steady →';
  List<Reasoning> get low => reasonings.where((r) => r.isActive && r.confidence >= 26 && r.confidence < 51).toList();

  final Risk risk;
  final String assessment;

  // Active = actually sent, not yet acknowledged. Confidence bands: 91+ critical, 76-90 high, 51-75 medium.
  List<String> get detectedLabels => {for (final r in [...critical, ...high]) r.category.label}.toList();
  List<Reasoning> get critical => reasonings.where((r) => r.isActive && r.confidence >= 91).toList();
  List<Reasoning> get high => reasonings.where((r) => r.isActive && r.confidence >= 76 && r.confidence < 91).toList();
  List<Reasoning> get medium => reasonings.where((r) => r.isActive && r.confidence >= 51 && r.confidence < 76).toList();

  final ImpactSummary impact;

  final int score;
  final OverallStatus status;
  final List<SensitiveItem> items;
  final TrackingSummary tracking;
  final String trend; // plain-language comparison with the previous period
  final String headline;
  final List<String> details;
  final List<String> actions; // at most 3
  final int blockedTotal;
  final List<Reasoning> reasonings;
  final int leftTotal; // personal-information items that actually left the device

  bool get trendImproved => trend.startsWith('Improved');
  bool get trendDecreased => trend.startsWith('Decreased');

  static const _groups = <(String, IconData, Set<PiiCategory>)>[
    ('Passwords', Icons.password, {PiiCategory.credential}),
    ('Credit cards', Icons.credit_card, {PiiCategory.creditCard}),
    ('Email addresses', Icons.email, {PiiCategory.email}),
    ('Phone numbers', Icons.phone, {PiiCategory.phone}),
    ('Personal documents', Icons.badge, {PiiCategory.ssn, PiiCategory.dob}),
  ];

  static ConsumerSummary build({
    required List<TransactionEvent> events,
    required bool Function(TransactionEvent) wasBlocked,
    required int score,
    int? previousScore,
    Set<String>? previousTrackerHosts,
  }) {
    final reasonings = ReasoningEngine.analyzeAll(events, wasBlocked);
    final items = <SensitiveItem>[];
    var left = 0;
    var protectedCount = 0;
    final alertNames = <String>[];

    for (final (title, icon, cats) in _groups) {
      final hits = events.where((e) => e.what.any((m) => cats.contains(m.category))).toList();
      final sent = hits.where((e) => !wasBlocked(e)).toList();
      protectedCount += hits.length - sent.length;
      final rs = reasonings.where((r) => cats.contains(r.category)).toList();
      final live = rs.where((r) => !r.blocked && !AckStore.instance.has(r.ackKey)).toList();
      int top(List<Reasoning> l) => l.fold(0, (m, r) => r.confidence > m ? r.confidence : m);
      final conf = rs.isEmpty ? null : top(live.isEmpty ? rs : live);
      final liveConf = top(live);

      // Alert needs strong evidence; weak detections are shown as reassurance rather than alarm.
      final risky = sent.any((e) => !e.encrypted || e.tracker != null || e.severity == Severity.critical);
      final level = live.isEmpty || liveConf < 26
          ? SafetyLevel.safe
          : (liveConf >= 76 || (liveConf >= 51 && risky) ? SafetyLevel.alert : SafetyLevel.warning);
      final reallySent = live.isNotEmpty && liveConf >= 26;

      if (reallySent) left++;
      if (level == SafetyLevel.alert) alertNames.add(title.toLowerCase());
      items.add(SensitiveItem(
        title,
        icon,
        level,
        hits.isEmpty
            ? 'Nothing found leaving your device'
            : !reallySent
                ? (sent.isEmpty
                    ? 'Found and stopped before it left your device'
                    : live.isEmpty
                        ? 'Reviewed and acknowledged by you'
                        : 'Looked like a match, but evidence suggests a false alarm')
                : level == SafetyLevel.alert
                    ? 'Likely sent to a company that should not have it'
                    : 'Sent, probably to a service you use. Worth a glance',
        conf,
      ));
    }

    final t = TrackingSummary();
    for (final e in events) {
      final tr = e.tracker;
      if (tr == null) continue;
      final blocked = wasBlocked(e);
      switch (tr.category) {
        case 'Advertising':
          t.advertisingSeen++;
          if (blocked) t.advertising++;
        case 'Telemetry':
          t.telemetrySeen++;
          if (blocked) t.telemetry++;
        default:
          t.trackersSeen++;
          if (blocked) t.trackers++;
      }
    }
    final blockedTotal = t.trackers + t.telemetry + t.advertising + protectedCount;

    final act = reasonings.where((r) => r.isActive).toList();
    final nCrit = act.where((r) => r.confidence >= 91).length;
    final nHigh = act.where((r) => r.confidence >= 76 && r.confidence < 91).length;
    final nMed = act.where((r) => r.confidence >= 51 && r.confidence < 76).length;
    final risk = nCrit > 0
        ? Risk.critical
        : nHigh > 0
            ? Risk.high
            : nMed > 0
                ? Risk.medium
                : act.any((r) => r.confidence >= 26)
                    ? Risk.low
                    : Risk.safe;
    // The score can never look healthier than the worst confirmed finding.
    final shownScore = switch (risk) {
      Risk.critical => score.clamp(0, 40),
      Risk.high => score.clamp(0, 60),
      Risk.medium => score.clamp(0, 80),
      _ => score,
    };
    final top = act.where((r) => r.confidence >= 76).toList();
    final plain = top.any((r) => r.unencrypted);
    final assessment = switch (risk) {
      Risk.critical || Risk.high =>
        'PrivacyWatch detected sensitive information that appears to have left your device${plain ? ' over unencrypted HTTP' : ''}. '
            '${risk == Risk.critical ? 'Immediate investigation is recommended.' : 'Please review it soon.'}',
      Risk.medium => 'Some personal information may have been sent, but the evidence is not conclusive. Review the findings below.',
      Risk.low => 'Only weak signs were found and they are probably false alarms. No action is needed.',
      Risk.safe => 'No personal information was found leaving your device.',
    };

    final status = OverallStatus.fromScore(shownScore);
    final trend = previousScore == null
        ? 'No earlier check to compare with yet. Save a snapshot to start tracking your progress.'
        : score > previousScore
            ? 'Improved by ${score - previousScore} points since your last check.'
            : score < previousScore
                ? 'Decreased by ${previousScore - score} points since your last check.'
                : 'Unchanged since your last check.';

    final headline = switch (status) {
      OverallStatus.strong => 'Your information is well protected.',
      OverallStatus.good => 'Your protection is good. Nothing urgent.',
      OverallStatus.moderate => 'Some information may be exposed. A few quick fixes will help.',
      OverallStatus.high => 'There are exposures to fix. Each fix raises your score right away.',
      OverallStatus.urgent => 'Several exposures need attention. The fixes below are quick and your score will recover as you apply them.',
    };
    final details = <String>[
      if (blockedTotal > 0) 'Good news: $blockedTotal attempt(s) to track you or collect data were blocked.',
      if (left == 0) 'No personal information was found leaving your device.',
      if (left > 0) '$left kind(s) of personal information were sent out. Some of this is normal when you sign in or shop.',
    ];

    final actions = <String>[
      if (alertNames.isNotEmpty) 'Review the app that sent your ${alertNames.first} and block it if you do not trust it.',
      if (alertNames.contains('passwords')) 'Change the password for any account you used recently.',
      if (alertNames.contains('credit cards')) 'Check your card statement and tell your bank if anything looks wrong.',
      if (t.advertisingSeen + t.trackersSeen + t.telemetrySeen > t.advertising + t.trackers + t.telemetry)
        'Turn on blocking for trackers that are still getting through.',
      if (left > 0 && alertNames.isEmpty) 'Look at the warnings below and confirm you recognise the apps involved.',
    ];
    if (actions.isEmpty) actions.add('Nothing to do. Keep PrivacyWatch running and check back later.');

    return ConsumerSummary._(shownScore, status, items, t, trend, headline, details, actions.take(3).toList(),
        blockedTotal, left, reasonings, ImpactSummary.build(events), risk, assessment,
        previousScore == null ? null : shownScore - previousScore,
        {for (final e in events) if (e.tracker != null) e.host}.length,
        {for (final e in events) if (e.tracker != null) e.host}.difference(previousTrackerHosts ?? {}).length);
  }
}

class ConsumerDashboard extends StatelessWidget {
  const ConsumerDashboard(this.s, {super.key, required this.onChanged, required this.onRemediate, this.wide = false, this.technical});
  final Widget? technical; // full-width technical details card, shown under the score and shield on wide screens
  final void Function(List<Reasoning>) onRemediate; // block the destination and mark the finding handled
  final bool wide; // desktop-width two-column layout
  final VoidCallback onChanged;
  final ConsumerSummary s;

  static Color _levelColor(SafetyLevel l) => switch (l) {
        SafetyLevel.safe => Colors.green.shade700,
        SafetyLevel.warning => Colors.amber.shade800,
        SafetyLevel.alert => Colors.red.shade700,
      };

  static String _confLabel(int c) =>
      'Confidence: $c% (${c >= 76 ? 'High' : c >= 51 ? 'Medium' : 'Low - may be a false alarm'})';

  @override
  Widget build(BuildContext context) {
    final active = {...s.critical, ...s.high, ...s.medium, ...s.low};
    final others = s.reasonings.where((r) => !active.contains(r)).toList();
    final fixable = s.critical.where((r) => r.impact.index <= Impact.low.index || r.impact == Impact.unknown).toList();
    final th = Theme.of(context).textTheme;
    final blocks = <String, Widget>{
      'exec': _pair(Card(
        color: s.risk.color.withValues(alpha: 0.10),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Wrap(crossAxisAlignment: WrapCrossAlignment.end, spacing: 32, runSpacing: 10, children: [
              _stat2('Privacy Score', '${s.score} / 100', th, big: true, color: s.status.color),
              _stat2('Status', s.status.label, th, color: s.status.color),
              _stat2('Change since last scan', s.scoreChangeText, th,
                  color: (s.scoreDelta ?? 0) > 0 ? Colors.green.shade700 : (s.scoreDelta ?? 0) < 0 ? Colors.red.shade700 : null),
              _stat2('Critical findings', '${s.critical.length}', th, big: true, color: s.critical.isEmpty ? Colors.green.shade700 : Risk.critical.color),
            ]),
            const SizedBox(height: 10),
            Wrap(spacing: 8, children: [
              _countChip('Critical', s.critical.length, Risk.critical.color),
              _countChip('High', s.high.length, Risk.high.color),
              _countChip('Medium', s.medium.length, Risk.medium.color),
              _countChip('Low', s.low.length, Colors.blue),
            ]),
            const SizedBox(height: 8),
            Text('Overall Risk: ${s.risk.label}. ${s.assessment}', style: th.bodyLarge),
            Text(s.headline, style: th.bodyMedium),
            if (fixable.isNotEmpty)
              Padding(
                padding: const EdgeInsets.only(top: 10),
                child: FilledButton.icon(
                  icon: const Icon(Icons.build_circle),
                  label: Text('Fix All Critical Issues (${fixable.length})'),
                  onPressed: () => _fixAll(context, fixable),
                ),
              ),
            if (s.critical.length > fixable.length)
              Padding(
                padding: const EdgeInsets.only(top: 4),
                child: Text('${s.critical.length - fixable.length} critical finding(s) may affect an app you use, so they need your confirmation one at a time.',
                    style: th.bodySmall),
              ),
            const Divider(height: 24),
            Wrap(spacing: 32, runSpacing: 8, children: [
              _stat2('Exposure trend', s.exposureTrend, th),
              _stat2('Trackers identified', '${s.trackerHosts}', th),
              _stat2('New tracking detected', '${s.newTrackers}', th),
            ]),
            if (s.newTrackers > 0)
              Padding(
                padding: const EdgeInsets.only(top: 6),
                child: Text(
                    'Additional trackers were discovered through analysis. Increased detection does not necessarily mean privacy has worsened.',
                    style: th.bodySmall),
              ),
            if (s.blockedTotal > 0 && s.risk.index >= Risk.high.index)
              Padding(
                padding: const EdgeInsets.only(top: 6),
                child: Text('Blocked trackers and telemetry were also observed, but they are not the primary concern in this report.',
                    style: th.bodySmall),
              ),
          ]),
        ),
      )),
      'critical': _fold('Critical findings', s.critical, th, context, open: true, empty: 'No critical findings. Nice work.'),
      'high': _fold('High findings', s.high, th, context, open: s.critical.length < 3, empty: 'No high findings.'),
      'medium': _fold('Medium findings', s.medium, th, context, empty: 'No medium findings.'),
      'low': _fold('Low findings', [...s.low, ...others], th, context, empty: 'Nothing here.',
          note: 'Includes low-confidence, blocked and acknowledged items.'),      'sensitive': _section('Your sensitive information', th, [
        for (final i in s.items)
          ListTile(
            dense: true,
            contentPadding: EdgeInsets.zero,
            leading: Icon(i.icon, color: _levelColor(i.level)),
            title: Text(i.title),
            subtitle: Text([i.detail, if (i.confidence != null) _confLabel(i.confidence!)].join('\n')),
            isThreeLine: i.confidence != null,
            trailing: Chip(
              visualDensity: VisualDensity.compact,
              backgroundColor: _levelColor(i.level),
              label: Text(i.level.name.toUpperCase(),
                  style: const TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.bold)),
            ),
          ),
      ]),
      'tracking': _section('Tracking protection', th, [
        Row(children: [
          _stat('Trackers blocked', s.tracking.trackers, s.tracking.trackersSeen, th),
          _stat('Telemetry blocked', s.tracking.telemetry, s.tracking.telemetrySeen, th),
          _stat('Ads blocked', s.tracking.advertising, s.tracking.advertisingSeen, th),
        ]),
        const SizedBox(height: 6),
        Text('Blocked means it was stopped and nothing was sent. The small "got through" note counts what was not stopped.',
            style: th.bodySmall),
      ]),
      'impact': _section('Functional impact summary', th, [
        if (s.impact.groups.isEmpty)
          const Text('Nothing has been blocked, so nothing should have stopped working.')
        else ...[
          Row(children: [
            _count('Websites blocked', s.impact.websites.length, th),
            _count('Apps affected', s.impact.apps.length, th),
            _count('Services affected', s.impact.services.length, th),
          ]),
          const SizedBox(height: 8),
          if (s.impact.top.isEmpty)
            Text('Good news: everything blocked is advertising, tracking or similar, which should not break anything.',
                style: th.bodyMedium)
          else ...[
            Text('Most impactful blocks', style: th.labelLarge),
            for (final g in s.impact.top)
              ListTile(
                dense: true,
                contentPadding: EdgeInsets.zero,
                leading: Icon(g.repeated ? Icons.report_problem : Icons.info_outline,
                    color: g.repeated ? Colors.orange.shade800 : null),
                title: Text(g.explanation),
                subtitle: Text('${g.host} | ${g.apps.join(', ')} | ${g.rules.join(', ')} | last ${_time(g.last!)}\n'
                    'May affect: ${g.affects}'),
                isThreeLine: true,
              ),
          ],
        ],
      ]),
      'trend': _section('Privacy trend', th, [
        Row(children: [
          Icon(
            s.trendImproved
                ? Icons.trending_up
                : s.trendDecreased
                    ? Icons.trending_down
                    : Icons.trending_flat,
            color: s.trendImproved
                ? Colors.green.shade700
                : s.trendDecreased
                    ? Colors.red.shade700
                    : Colors.grey,
          ),
          const SizedBox(width: 8),
          Expanded(child: Text(s.trend, style: th.bodyLarge)),
        ]),
      ]),
      'banner': s.risk.index <= Risk.medium.index ? ProtectionBanner(s) : const SizedBox.shrink(),
      'protectedHead': Padding(
        padding: const EdgeInsets.fromLTRB(4, 8, 4, 0),
        child: Text('Protected and blocked activity', style: th.titleMedium?.copyWith(fontWeight: FontWeight.bold)),
      ),
          };
    List<Widget> col(List<String> keys) => [for (final k in keys) blocks[k]!];
    const order = ['critical', 'high', 'medium', 'low'];
    final side = ['sensitive', 'protectedHead', if (!wide) 'banner', 'tracking', 'impact', 'trend'];
    if (!wide) {
      return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: col(['exec', ...order, ...side]));
    }
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      blocks['exec']!,
      Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: col(order))),
        Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: col(side))),
      ]),
    ]);
  }

  /// On wide screens the shield status sits beside the score as its own card.
  /// Wide screens: shield beside the score (equal height), technical details full width below them.
  /// The expandable card sits outside the equal-height row so expanding it cannot break layout.
  Widget _pair(Widget main) {
    if (!wide) return main;
    final shield = s.risk.index <= Risk.medium.index;
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      if (shield)
        IntrinsicHeight(
          child: Row(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            Expanded(flex: 3, child: main),
            const SizedBox(width: 16),
            Expanded(flex: 2, child: ProtectionBanner(s)),
          ]),
        )
      else
        main,
      ?technical,
    ]);
  }

  Widget _stat2(String label, String value, TextTheme th, {bool big = false, Color? color}) => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(label, style: th.labelMedium),
          Text(value, style: (big ? th.displaySmall : th.titleLarge)?.copyWith(fontWeight: FontWeight.bold, color: color)),
        ],
      );

  static Color _sevColor(Reasoning r) => r.confidence >= 91
      ? Risk.critical.color
      : r.confidence >= 76
          ? Risk.high.color
          : r.confidence >= 51
              ? Colors.amber.shade700
              : Colors.blue;

  Widget _fold(String title, List<Reasoning> list, TextTheme th, BuildContext context,
          {bool open = false, required String empty, String? note}) =>
      Card(
        child: Theme(
          data: Theme.of(context).copyWith(dividerColor: Colors.transparent),
          child: ExpansionTile(
            initiallyExpanded: open,
            title: Text('$title (${list.length})', style: th.titleMedium?.copyWith(fontWeight: FontWeight.bold)),
            childrenPadding: const EdgeInsets.fromLTRB(10, 0, 10, 10),
            children: [
              if (note != null && list.isNotEmpty) Align(alignment: Alignment.centerLeft, child: Text(note, style: th.bodySmall)),
              if (list.isEmpty) Align(alignment: Alignment.centerLeft, child: Text(empty)),
              for (final r in list) _card(context, r, th),
            ],
          ),
        ),
      );

  /// Compact card: severity + title, then the action and its buttons first.
  Widget _card(BuildContext context, Reasoning r, TextTheme th) {
    final acked = AckStore.instance.has(r.ackKey);
    return Card(
      margin: const EdgeInsets.symmetric(vertical: 4),
      color: Theme.of(context).colorScheme.surface,
      child: InkWell(
        onTap: () => _details(context, r, th),
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: _body(context, r, th, acked, compact: true),
        ),
      ),
    );
  }

  Widget _body(BuildContext context, Reasoning r, TextTheme th, bool acked, {required bool compact, VoidCallback? done}) {
    final canFix = r.isActive && r.recommendation.index >= RecommendedAction.restrict.index;
    final done0 = done ?? () {};
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Row(children: [
        Icon(Icons.circle, size: 12, color: r.blocked || acked ? Colors.grey : _sevColor(r)),
        const SizedBox(width: 8),
        Text('${r.severity.label.toUpperCase()}  ', style: th.labelLarge?.copyWith(color: _sevColor(r), fontWeight: FontWeight.bold)),
        Expanded(child: Text(r.title, style: th.titleSmall?.copyWith(fontWeight: FontWeight.bold))),
      ]),
      const SizedBox(height: 6),
      Container(
        width: double.infinity,
        padding: const EdgeInsets.all(8),
        decoration: BoxDecoration(color: Colors.blue.withValues(alpha: 0.08), borderRadius: BorderRadius.circular(6)),
        child: Text('Recommended action: ${r.recommendation.label}. ${r.action}', style: th.bodyMedium?.copyWith(fontWeight: FontWeight.w600)),
      ),
      const SizedBox(height: 6),
      Wrap(spacing: 8, runSpacing: 4, children: [
        if (canFix)
          FilledButton.icon(
              icon: const Icon(Icons.shield, size: 16),
              onPressed: () {
                _remediateOne(context, r);
                done0();
              },
              label: const Text('Remediate Now')),
        if (!r.blocked && !acked) ...[
          OutlinedButton(
              onPressed: () {
                final keys = [
                  for (final x in s.reasonings)
                    if (x.app == r.app && x.isActive) x.ackKey
                ];
                AckStore.instance.add(keys);
                done0();
                onChanged();
              },
              child: const Text('Trust Application')),
          OutlinedButton(
              onPressed: () {
                AckStore.instance.add([r.ackKey]);
                done0();
                onChanged();
              },
              child: const Text('Ignore')),
        ] else
          Chip(label: Text(r.blocked ? 'Blocked' : 'Acknowledged')),
        if (acked)
          TextButton(
              onPressed: () {
                AckStore.instance.remove(r.ackKey);
                done0();
                onChanged();
              },
              child: const Text('Undo')),
      ]),
      const SizedBox(height: 6),
      Text(r.summaryLine, style: th.bodyMedium),
      if (compact) Text('Tap for why this was flagged and details.', style: th.bodySmall),
    ]);
  }
  Future<bool> _confirm(BuildContext context, String title, String body, String yes) async =>
      await showDialog<bool>(
        context: context,
        builder: (c) => AlertDialog(
          title: Text(title),
          content: SizedBox(width: 460, child: Text(body)),
          actions: [
            TextButton(onPressed: () => Navigator.pop(c, false), child: const Text('Cancel')),
            FilledButton(onPressed: () => Navigator.pop(c, true), child: Text(yes)),
          ],
        ),
      ) ??
      false;

  Future<void> _remediateOne(BuildContext context, Reasoning r) async {
    final risky = r.impact == Impact.medium || r.impact == Impact.high;
    final ok = !risky ||
        await _confirm(context, 'Block ${r.host}?', 'This may affect $r.app. ${r.impactText}', 'Block it');
    if (ok) onRemediate([r]);
  }

  Future<void> _fixAll(BuildContext context, List<Reasoning> list) async {
    final hosts = {for (final r in list) r.host}.join(', ');
    final ok = await _confirm(
        context,
        'Fix ${list.length} critical issue(s)?',
        'PrivacyWatch will block these destinations: $hosts. None of them is expected to break an app you use. '
            'You can unblock any of them later from Blocked items.',
        'Fix all');
    if (ok) onRemediate(list);
  }

  Future<void> _details(BuildContext context, Reasoning r, TextTheme th) => showDialog<void>(
        context: context,
        builder: (c) {
          final acked = AckStore.instance.has(r.ackKey);
          Widget head(String t) =>
              Padding(padding: const EdgeInsets.only(top: 10, bottom: 2), child: Text(t, style: th.labelLarge));
          Widget clues(List<Clue> l) => Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [for (final k in l) Text(k.line, style: th.bodyMedium?.copyWith(color: k.found ? null : Colors.black54))]);
          Widget fold(String t, List<Widget> kids) => ExpansionTile(
              tilePadding: EdgeInsets.zero,
              title: Text(t),
              expandedCrossAxisAlignment: CrossAxisAlignment.start,
              children: kids);
          return AlertDialog(
            content: SizedBox(
              width: 600,
              child: SingleChildScrollView(
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  _body(context, r, th, acked, compact: false, done: () => Navigator.pop(c)),
                  head('Why this was flagged'),
                  Text('${r.raw} Confidence ${r.confidence}% (${r.confidenceBand}). ${r.assessment}'),
                  head('If you block it: functional impact ${r.impact.label}'),
                  Text(r.impactText),
                  const Divider(),
                  fold('Evidence', [head('Detection evidence'), clues(r.evidence), head('Context analysis'), clues(r.context)]),
                  fold('Technical details', [for (final w in r.why) Text('• $w'), Text('Destination: ${r.host}  |  App: ${r.app}')]),
                  fold('Raw network activity', [for (final l in r.rawLines) SelectableText(l, style: th.bodySmall)]),
                ]),
              ),
            ),
            actions: [TextButton(onPressed: () => Navigator.pop(c), child: const Text('Close'))],
          );
        },
      );
  Widget _countChip(String label, int n, Color c) => Chip(
        visualDensity: VisualDensity.compact,
        backgroundColor: n > 0 ? c : Colors.black12,
        label: Text('$label $n',
            style: TextStyle(color: n > 0 ? Colors.white : Colors.black87, fontWeight: FontWeight.bold)),
      );
  static String _time(DateTime t) =>
      '${t.hour.toString().padLeft(2, '0')}:${t.minute.toString().padLeft(2, '0')}';

  Widget _count(String label, int n, TextTheme th) => Expanded(
        child: Column(children: [
          Text('$n', style: th.headlineSmall?.copyWith(fontWeight: FontWeight.bold)),
          Text(label, style: th.bodySmall, textAlign: TextAlign.center),
        ]),
      );

  Widget _stat(String label, int blocked, int seen, TextTheme th) => Expanded(
        child: Column(children: [
          Text('$blocked', style: th.headlineSmall?.copyWith(color: Colors.green.shade700, fontWeight: FontWeight.bold)),
          Text(label, style: th.bodySmall, textAlign: TextAlign.center),
          if (seen > blocked) Text('${seen - blocked} got through', style: th.labelSmall?.copyWith(color: Colors.orange.shade800)),
        ]),
      );

  Widget _section(String title, TextTheme th, List<Widget> children) => Card(
        child: Theme(
          data: ThemeData(dividerColor: Colors.transparent),
          child: ExpansionTile(
            initiallyExpanded: title == 'Your sensitive information',
            title: Text(title, style: th.titleMedium?.copyWith(fontWeight: FontWeight.bold)),
            childrenPadding: const EdgeInsets.fromLTRB(14, 0, 14, 12),
            expandedCrossAxisAlignment: CrossAxisAlignment.start,
            children: children,
          ),
        ),
      );}
