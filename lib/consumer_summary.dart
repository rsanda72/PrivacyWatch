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
  excellent('Excellent', Colors.green),
  good('Good', Colors.lightGreen),
  attention('Attention Needed', Colors.orange),
  highRisk('High Risk', Colors.red);

  const OverallStatus(this.label, this.color);
  final String label;
  final Color color;

  static OverallStatus fromScore(int s) =>
      s >= 90 ? excellent : s >= 75 ? good : s >= 50 ? attention : highRisk;
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

class ConsumerSummary {
  ConsumerSummary._(this.score, this.status, this.items, this.tracking, this.trend, this.headline,
      this.details, this.actions, this.blockedTotal, this.leftTotal, this.reasonings, this.impact);

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

    final status = OverallStatus.fromScore(score);
    final trend = previousScore == null
        ? 'No earlier check to compare with yet. Save a snapshot to start tracking your progress.'
        : score > previousScore
            ? 'Improved by ${score - previousScore} points since your last check.'
            : score < previousScore
                ? 'Decreased by ${previousScore - score} points since your last check.'
                : 'Unchanged since your last check.';

    final headline = switch (status) {
      OverallStatus.excellent => 'You are safe. Nothing personal left your device.',
      OverallStatus.good => 'You are mostly safe. Nothing urgent.',
      OverallStatus.attention => 'Some personal information may have left your device.',
      OverallStatus.highRisk => 'Sensitive information left your device. Please take action.',
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

    return ConsumerSummary._(score, status, items, t, trend, headline, details, actions.take(3).toList(),
        blockedTotal, left, reasonings, ImpactSummary.build(events));
  }
}

class ConsumerDashboard extends StatelessWidget {
  const ConsumerDashboard(this.s, {super.key, required this.onChanged, this.wide = false});
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
    final pending = s.reasonings.where((r) => r.needsAttention && !AckStore.instance.has(r.ackKey)).toList();
    final acked = s.reasonings.where((r) => AckStore.instance.has(r.ackKey)).toList();
    final th = Theme.of(context).textTheme;
    final c = s.status.color;
    final blocks = <String, Widget>{
      'banner': ProtectionBanner(s),
      'header': Card(
        color: c.withValues(alpha: 0.12),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Row(children: [
            Text('${s.score}', style: th.displayMedium?.copyWith(color: c, fontWeight: FontWeight.bold)),
            const SizedBox(width: 4),
            Text('/ 100', style: th.titleMedium),
            const SizedBox(width: 16),
            Expanded(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(s.status.label, style: th.titleLarge?.copyWith(color: c, fontWeight: FontWeight.bold)),
                const SizedBox(height: 4),
                Text(s.headline, style: th.bodyLarge),
              ]),
            ),
          ]),
        ),
      ),
      'happened': _section('What happened', th, [for (final d in s.details) _bullet(d, th)]),
      'sensitive': _section('Your sensitive information', th, [
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
      'actions': _section('What you can do', th, [
        for (var i = 0; i < s.actions.length; i++)
          ListTile(
            dense: true,
            contentPadding: EdgeInsets.zero,
            leading: CircleAvatar(radius: 12, child: Text('${i + 1}', style: const TextStyle(fontSize: 12))),
            title: Text(s.actions[i]),
          ),
      ]),
      'reasoning': _section('Explain the reasoning', th, [
        Text(
            'A detection is not a confirmation. For each finding we show why it was flagged and how sure we are.',
            style: th.bodySmall),
        if (s.reasonings.isEmpty) const Padding(padding: EdgeInsets.only(top: 8), child: Text('Nothing was flagged.')),
        if (pending.length > 1)
          Align(
            alignment: Alignment.centerRight,
            child: TextButton.icon(
              icon: const Icon(Icons.done_all),
              label: Text('Acknowledge all (${pending.length})'),
              onPressed: () {
                AckStore.instance.add(pending.map((r) => r.ackKey));
                onChanged();
              },
            ),
          ),
        for (final r in s.reasonings.where((r) => !AckStore.instance.has(r.ackKey)).take(15)) _reasoningTile(r, th),
        if (acked.isNotEmpty)
          ExpansionTile(
            tilePadding: EdgeInsets.zero,
            title: Text('Acknowledged (${acked.length})'),
            children: [for (final r in acked) _reasoningTile(r, th)],
          ),
      ]),
    };
    List<Widget> col(List<String> keys) => [for (final k in keys) blocks[k]!];
    if (!wide) {
      return Column(crossAxisAlignment: CrossAxisAlignment.stretch,
          children: col(['banner', 'header', 'happened', 'sensitive', 'tracking', 'impact', 'trend', 'actions', 'reasoning']));
    }
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      blocks['banner']!,
      blocks['header']!,
      Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: col(['happened', 'sensitive', 'tracking', 'trend']))),
        Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: col(['actions', 'impact', 'reasoning']))),
      ]),
    ]);
  }

  Widget _reasoningTile(Reasoning r, TextTheme th) {
    final isAcked = AckStore.instance.has(r.ackKey);
    Widget head(String t) => Padding(
        padding: const EdgeInsets.only(top: 10, bottom: 2), child: Text(t, style: th.labelLarge));
    Widget clues(List<Clue> l) => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [for (final c in l) Text(c.line, style: th.bodyMedium?.copyWith(color: c.found ? null : Colors.black54))]);
    return ExpansionTile(
      leading: r.needsAttention && !isAcked ? const Icon(Icons.circle, size: 10, color: Colors.red) : null,
      tilePadding: EdgeInsets.zero,
      childrenPadding: const EdgeInsets.only(bottom: 8),
      expandedCrossAxisAlignment: CrossAxisAlignment.start,
      title: Text(r.title),
      subtitle: Text('${r.blocked ? 'Blocked' : 'Sent'} | ${r.confidence}% ${r.confidenceBand} confidence | ${r.recommendation.label}'),
      children: [
        head('Raw detection'),
        Text(r.raw),
        head('Detection evidence'),
        clues(r.evidence),
        head('Context analysis'),
        clues(r.context),
        head('Confidence'),
        Text('${r.confidence}% (${r.confidenceBand}) - rated ${r.severity.label}'),
        head('Assessment'),
        Text(r.assessment),
        head('Recommended action: ${r.recommendation.label}'),
        Text(r.action),
        head('Functional impact: ${r.impact.label}'),
        Text(r.impactText),
        head('Why this action was recommended'),
        for (final w in r.why) Text('• $w'),
        if (r.needsAttention)
          Align(
            alignment: Alignment.centerRight,
            child: isAcked
                ? TextButton(
                    onPressed: () {
                      AckStore.instance.remove(r.ackKey);
                      onChanged();
                    },
                    child: const Text('Undo acknowledge'))
                : FilledButton.icon(
                    icon: const Icon(Icons.check),
                    label: const Text('Acknowledge'),
                    onPressed: () {
                      AckStore.instance.add([r.ackKey]);
                      onChanged();
                    },
                  ),
          ),
      ],
    );
  }

  static String _time(DateTime t) =>
      '${t.hour.toString().padLeft(2, '0')}:${t.minute.toString().padLeft(2, '0')}';

  Widget _count(String label, int n, TextTheme th) => Expanded(
        child: Column(children: [
          Text('$n', style: th.headlineSmall?.copyWith(fontWeight: FontWeight.bold)),
          Text(label, style: th.bodySmall, textAlign: TextAlign.center),
        ]),
      );

  Widget _bullet(String t, TextTheme th) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 2),
        child: Text(t, style: th.bodyLarge),
      );

  Widget _stat(String label, int blocked, int seen, TextTheme th) => Expanded(
        child: Column(children: [
          Text('$blocked', style: th.headlineSmall?.copyWith(color: Colors.green.shade700, fontWeight: FontWeight.bold)),
          Text(label, style: th.bodySmall, textAlign: TextAlign.center),
          if (seen > blocked) Text('${seen - blocked} got through', style: th.labelSmall?.copyWith(color: Colors.orange.shade800)),
        ]),
      );

  Widget _section(String title, TextTheme th, List<Widget> children) => Card(
        child: Padding(
          padding: const EdgeInsets.all(14),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(title, style: th.titleMedium?.copyWith(fontWeight: FontWeight.bold)),
            const SizedBox(height: 6),
            ...children,
          ]),
        ),
      );
}
