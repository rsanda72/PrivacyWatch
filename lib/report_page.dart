import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'block_advice.dart';
import 'traffic_trend.dart';
import 'audit_view.dart';
import 'consumer_summary.dart';
import 'reasoning.dart';
import 'core/app_blocker.dart';
import 'core/audit_store.dart';
import 'core/ack_store.dart';
import 'core/event.dart';
import 'core/pii_detector.dart';
import 'core/tracker_classifier.dart';
import 'critical_dialog.dart';

Color severityColor(Severity s) => switch (s) {
      Severity.critical => Colors.red.shade800,
      Severity.high => Colors.deepOrange,
      Severity.medium => Colors.amber.shade700,
      Severity.low => Colors.blue,
      Severity.info => Colors.grey,
    };

class SeverityChip extends StatelessWidget {
  const SeverityChip(this.severity, {super.key});
  final Severity severity;

  @override
  Widget build(BuildContext context) => Chip(
        label: Text(severity.label, style: const TextStyle(color: Colors.white, fontSize: 12)),
        backgroundColor: severityColor(severity),
        visualDensity: VisualDensity.compact,
        padding: EdgeInsets.zero,
      );
}

/// Phone-sized column used on every platform so desktop and mobile look the same.
const _maxWidth = 560.0;

class ReportPage extends StatefulWidget {
  const ReportPage({super.key, required this.liveEvents, required this.liveCount,   this.blocker, this.dataDir});
    final Directory? dataDir; // where saved captures live, for the traffic trend
    final List<TransactionEvent> liveEvents; // still receiving captures while the report is open
  final ValueListenable<int> liveCount;
  final AppBlocker? blocker;

  @override
  State<ReportPage> createState() => _ReportPageState();
}

String _appName(TransactionEvent e) =>
    (e.app ?? 'unknown app').replaceAll(RegExp(r' \(PID \d+\)'), '');

bool _isBlocked(TransactionEvent e) => e.how.startsWith('BLOCKED');

/// "4 contact(s), all blocked - nothing was sent" style summary.
String _blockedSummary(List<TransactionEvent> l) {
  final n = l.where(_isBlocked).length;
  if (n == 0) return '${l.length} contact(s), none blocked';
  if (n == l.length) return '${l.length} contact(s), all blocked - nothing was sent';
  return '${l.length} contact(s), $n blocked, ${l.length - n} got through';
}

class _TableRow {
  const _TableRow(this.name, this.events, this.onTap);
  final String name;
  final List<TransactionEvent> events;
  final VoidCallback onTap;
}

class _Agg {
  _Agg(List<TransactionEvent> events) {
    for (final s in Severity.values) {
      bySeverity[s] = 0;
    }
    for (final e in events) {
      bySeverity[e.severity] = bySeverity[e.severity]! + 1;
      apps.putIfAbsent(_appName(e), () => []).add(e);
      final t = e.tracker;
      if (t != null) trackers.putIfAbsent(t.category, () => []).add(e);
      if (e.what.isEmpty) continue;
      dests.putIfAbsent(e.who.split(' | ').first, () => []).add(e);
      for (final c in e.what.map((m) => m.category).toSet()) {
        byCategory.putIfAbsent(c, () => []).add(e);
      }
    }
  }

  final bySeverity = <Severity, int>{};
  final byCategory = <PiiCategory, List<TransactionEvent>>{};
  final dests = <String, List<TransactionEvent>>{};
  final apps = <String, List<TransactionEvent>>{};
  final trackers = <String, List<TransactionEvent>>{}; // keyed by tracker category

  List<PiiCategory> get cats =>
      byCategory.keys.toList()..sort((a, b) => b.severity.rank.compareTo(a.severity.rank));

  List<MapEntry<String, List<TransactionEvent>>> get destList => dests.entries.toList()
    ..sort((a, b) => worst(b.value).rank.compareTo(worst(a.value).rank));

  List<MapEntry<String, List<TransactionEvent>>> get appList =>
      apps.entries.toList()..sort((a, b) => b.value.length.compareTo(a.value.length));

  List<String> get trackerCats => [
        ...TrackerClassifier.categoryOrder.where(trackers.containsKey),
        ...trackers.keys.where((c) => !TrackerClassifier.categoryOrder.contains(c)),
      ];

  static Severity worst(List<TransactionEvent> l) =>
      l.map((e) => e.severity).reduce((a, b) => a.rank >= b.rank ? a : b);
}

int _sum(List<TransactionEvent> l, int Function(TransactionEvent) f) => l.fold(0, (a, e) => a + f(e));
String _bytes(int b) => TransactionEvent.formatBytes(b);

class _ReportPageState extends State<ReportPage> {
  late List<TransactionEvent> events = List.of(widget.liveEvents);

  @override
  void initState() {
    super.initState();
    final d = widget.dataDir;
    if (d != null) {
      AuditStore.instance.attach(File('${d.path}/audit.json'));
      AckStore.instance.attach(File('${d.path}/acks.json'));
    }
  }

  @override
  Widget build(BuildContext context) {
    final a = _Agg(events);
    final topCat = a.cats.isEmpty ? null : a.cats.first;

    return Scaffold(
      appBar: AppBar(title: const Text('Report'), actions: [
        IconButton(
          tooltip: 'Copy full report',
          onPressed: () => _copy(_reportText(a), 'Full report copied'),
          icon: const Icon(Icons.copy),
        ),
        PopupMenuButton<String>(
          tooltip: 'Options',
          onSelected: (v) {
            switch (v) {
              case 'refresh':
                setState(() => events = List.of(widget.liveEvents));
              case 'blocked':
                _openBlocked();
              case 'audit':
                _openAuditList();
              case 'personal':
                _show('Personal data', _personalData);
              case 'who':
                _show('Who received it', _destinations);
              case 'apps':
                _show('Apps & data volume', _applications);
              case 'tracking':
                _show('Behavioral tracking', _tracking);
              case 'traffic':
                _show('Monitored Privacy Traffic', _trafficDetail);
              case 'copy':
                _copy(_reportText(a), 'Full report copied');
            }
          },
          itemBuilder: (_) => const [
            PopupMenuItem(value: 'refresh', child: ListTile(leading: Icon(Icons.refresh), title: Text('Refresh'))),
            PopupMenuItem(value: 'blocked', child: ListTile(leading: Icon(Icons.block), title: Text('Blocked items'))),
            PopupMenuItem(value: 'audit', child: ListTile(leading: Icon(Icons.fact_check), title: Text('Audit reports'))),
            PopupMenuItem(value: 'personal', child: ListTile(leading: Icon(Icons.badge), title: Text('Personal data'))),
            PopupMenuItem(value: 'who', child: ListTile(leading: Icon(Icons.send), title: Text('Who received it'))),
            PopupMenuItem(value: 'tracking', child: ListTile(leading: Icon(Icons.visibility), title: Text('Behavioral tracking'))),
            PopupMenuItem(value: 'apps', child: ListTile(leading: Icon(Icons.apps), title: Text('Apps & data volume'))),
            PopupMenuItem(value: 'traffic', child: ListTile(leading: Icon(Icons.swap_vert), title: Text('Monitored Privacy Traffic'))),
            PopupMenuItem(value: 'copy', child: ListTile(leading: Icon(Icons.copy), title: Text('Copy full report'))),
          ],
        ),
      ]),
      body: LayoutBuilder(builder: (context, box) {
        final wide = box.maxWidth >= 900;
        return Center(
        child: ConstrainedBox(
          constraints: BoxConstraints(maxWidth: wide ? 1500 : _maxWidth),
          child: ListView(padding: const EdgeInsets.all(12), children: [
            ConsumerDashboard(wide: wide, onChanged: () => setState(() {}), onRemediate: _remediate, ConsumerSummary.build(
              previousTrackerHosts: {
                for (final i in AuditStore.instance.snapshots.firstOrNull?.items ?? const <AuditItem>[])
                  if (i.category != null) i.host
              },
              events: events,
              wasBlocked: _isBlocked,
              score: _scoreFor(_openNow),
              previousScore: AuditStore.instance.snapshots.firstOrNull?.score,
            )),
            const SizedBox(height: 8),
            Theme(
              data: Theme.of(context).copyWith(dividerColor: Colors.transparent),
              child: ExpansionTile(
                title: const Text('Technical details'),
                subtitle: const Text('For advanced users: destinations, apps and traffic'),
                childrenPadding: const EdgeInsets.only(bottom: 8),
                children: [_technicalDetails(a, topCat, wide)],
              ),
            ),
          ]),
        ),
      );}),
    );
  }

  Widget _technicalDetails(_Agg a, PiiCategory? topCat, bool wide) {
    return Column(children: [
            _liveBanner(),
            const SizedBox(height: 8),
            _summaryCard(a),
            const SizedBox(height: 8),
            Wrap(spacing: 6, runSpacing: 0, alignment: WrapAlignment.center, children: [
              for (final s in Severity.values.reversed)
                ActionChip(
                  visualDensity: VisualDensity.compact,
                  avatar: CircleAvatar(backgroundColor: severityColor(s), radius: 6),
                  label: Text('${s.label} ${a.bySeverity[s]}', style: const TextStyle(fontSize: 12)),
                  onPressed: () => _show('${s.label} (${a.bySeverity[s]})', (c, _) => _severityList(c, s)),
                ),
            ]),
            const SizedBox(height: 8),
            GridView.count(
              crossAxisCount: wide ? 4 : 2,
              shrinkWrap: true,
              physics: const NeverScrollableScrollPhysics(),
              mainAxisSpacing: 10,
              crossAxisSpacing: 10,
              childAspectRatio: 1.55,
              children: [
                _QuadCard(
                  icon: Icons.badge,
                  title: 'Personal data',
                  big: '${a.cats.length}',
                  unit: 'type(s) found',
                  color: topCat == null ? Colors.green : severityColor(topCat.severity),
                  lines: [
                    if (topCat == null) 'None detected yet' else 'Worst: ${topCat.label}',
                    for (final c in a.cats.skip(1).take(1)) c.label,
                  ],
                  traffic: _traffic(a.byCategory.values.expand((l) => l).toSet().toList()),
                  onTap: () => _show('Personal data', _personalData),
                ),
                _QuadCard(
                  icon: Icons.send,
                  title: 'Who received it',
                  big: '${a.dests.length}',
                  unit: 'destination(s)',
                  color: a.dests.isEmpty ? Colors.green : severityColor(_Agg.worst(a.dests.values.expand((e) => e).toList())),
                  lines: [
                    if (a.dests.isEmpty) 'Nobody yet',
                    for (final d in a.destList.take(2)) d.key,
                  ],
                  traffic: _traffic(a.dests.values.expand((l) => l).toSet().toList()),
                  onTap: () => _show('Who received it', _destinations),
                ),
                _QuadCard(
                  icon: Icons.visibility,
                  title: 'Behavioral tracking',
                  big: '${a.trackers.values.fold<int>(0, (n, l) => n + l.length)}',
                  unit: 'tracker contact(s), ${a.trackers.values.expand((l) => l).where(_isBlocked).length} blocked',
                  color: a.trackers.isEmpty ? Colors.green : Colors.blue,
                  lines: [
                    if (a.trackers.isEmpty) 'None seen - tap to block ahead',
                    for (final c in a.trackerCats.take(2))
                      '$c (${a.trackers[c]!.length}${a.trackers[c]!.every(_isBlocked) ? ', blocked' : ''})',
                  ],
                  traffic: _traffic(a.trackers.values.expand((l) => l).toList()),
                  onTap: () => _show('Behavioral tracking', _tracking),
                ),
                _QuadCard(
                  icon: Icons.apps,
                  title: 'Apps & data volume',
                  big: '${a.apps.length}',
                  unit: 'app(s)',
                  color: Colors.teal,
                  lines: [
                    for (final p in a.appList.take(2)) '${p.key} (${p.value.length} tx)',
                  ],
                  traffic: _traffic(events),
                  onTap: () => _show('Apps & data volume', _applications),
                ),
              ],
            ),
            const SizedBox(height: 10),
            _blockedCard(),
            const SizedBox(height: 10),
            _trafficCard(a),
            const SizedBox(height: 8),
            Text(
              'Tap a card for details. Severity is based on the data type; plain HTTP is raised one level because it is '
              'unencrypted. HTTPS contents are not decrypted, so they are not analysed.',
              style: Theme.of(context).textTheme.bodySmall,
              textAlign: TextAlign.center,
            ),
    ]);
  }

  /// A destination counts as open when its traffic was not refused and it is not blocked now.
  bool _openNow(TransactionEvent e) => !_isBlocked(e) && !(widget.blocker?.isHostBlocked(e.host) ?? false);

  void _remediate(List<Reasoning> list) {
    for (final r in list) {
      widget.blocker?.blockHost(r.host);
    }
    AckStore.instance.add([for (final r in list) r.ackKey]);
    setState(() {});
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
        content: Text('Blocked ${{for (final r in list) r.host}.join(', ')}. You can undo this from Blocked items.')));
  }

  int _scoreFor(bool Function(TransactionEvent) open) {
    final exposed = <String, Severity>{};
    final trackerHosts = <String>{};
    for (final e in events.where(open)) {
      if (e.what.isNotEmpty && e.severity.rank >= Severity.medium.rank) {
        final cur = exposed[e.host];
        if (cur == null || e.severity.rank > cur.rank) exposed[e.host] = e.severity;
      }
      if (e.tracker != null) trackerHosts.add(e.host);
    }
    final crit = exposed.values.where((s) => s == Severity.critical).length;
    final high = exposed.values.where((s) => s == Severity.high).length;
    return (100 - (crit * 20).clamp(0, 60) - (high * 8).clamp(0, 20)).clamp(0, 100);
  }

  /// The privacy state right now: every tracker or personal-data destination seen, and whether it is blocked.
  AuditSnapshot _liveSnapshot() {
    events = List.of(widget.liveEvents); // always the latest capture, not the copy from when the page opened
    final byHost = <String, List<TransactionEvent>>{};
    for (final e in events.where((e) => e.what.isNotEmpty || e.tracker != null)) {
      byHost.putIfAbsent(e.host, () => []).add(e);
    }
    final items = [
      for (final h in byHost.entries)
        AuditItem(
          host: h.key,
          blocked: widget.blocker?.isHostBlocked(h.key) ?? false,
          sent: h.value.where((e) => !_isBlocked(e)).length,
          refused: h.value.where(_isBlocked).length,
          category: h.value.first.tracker?.category,
          owner: h.value.first.tracker?.owner,
          severity: h.value.any((e) => e.what.isNotEmpty)
              ? _Agg.worst(h.value.where((e) => e.what.isNotEmpty).toList()).label
              : null,
          dataTypes: {for (final e in h.value) ...e.what.map((m) => m.category.label)}.toList(),
        ),
    ]..sort((a, b) => a.host.compareTo(b.host));
    return AuditSnapshot(
      id: 'Now (live)',
      time: DateTime.now(),
      score: _scoreFor(_openNow),
      requestsChecked: events.length,
      blockedDestinations: widget.blocker?.hosts.length ?? 0,
      items: items,
    );
  }

  void _takeSnapshot() {
    final live = _liveSnapshot();
    final s = AuditStore.instance.add(
      score: live.score,
      requestsChecked: live.requestsChecked,
      blockedDestinations: live.blockedDestinations,
      items: live.items,
    );
    setState(() {});
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Audit snapshot ${s.id} saved')));
  }

  void _openAuditList() => _show(
        'Audit',
        (ctx, rebuild) => AuditView(
          live: _liveSnapshot,
          onCopy: (t) => _copy(t, 'Audit comparison copied'),
          onSnapshot: () {
            _takeSnapshot();
            rebuild();
          },
          onChanged: rebuild,
        ),
      );

  String _two(int n) => n.toString().padLeft(2, '0');
  String _stamp(DateTime t) => '${t.year}-${_two(t.month)}-${_two(t.day)} ${_two(t.hour)}:${_two(t.minute)}:${_two(t.second)}';

  /// Google/Amazon-style summary: one rating, the few findings that matter, and what to do about them.
  Widget _summaryCard(_Agg a) {
    final b = widget.blocker;
    bool open(TransactionEvent e) => !_isBlocked(e) && !(b?.isHostBlocked(e.host) ?? false);

    // Personal data that reached a destination that is still not blocked, worst first.
    final exposed = <String, List<TransactionEvent>>{};
    for (final e in events.where((e) => e.what.isNotEmpty && open(e) && e.severity.rank >= Severity.medium.rank)) {
      exposed.putIfAbsent(e.host, () => []).add(e);
    }
    final exposedList = exposed.entries.toList()
      ..sort((x, y) => _Agg.worst(y.value).rank.compareTo(_Agg.worst(x.value).rank));

    final openTrackerCats = <String>[
      for (final c in TrackerClassifier.categoryOrder)
        if ((a.trackers[c] ?? []).any(open)) c,
    ];
    final openTrackerHosts = a.trackers.values.expand((l) => l).where(open).map((e) => e.host).toSet();

    final score = _scoreFor(open);
    final (Color color, String grade, String headline) = score >= 85
        ? (Colors.green.shade700, 'Good', 'Your privacy looks good')
        : score >= 60
            ? (Colors.amber.shade800, 'Needs attention', 'A few things need your attention')
            : (Colors.red.shade800, 'At risk', 'Personal data is being sent out');

    final totalSent = events.where((e) => (e.what.isNotEmpty || e.tracker != null) && open(e)).length;
    final stopped = events.where((e) => (e.what.isNotEmpty || e.tracker != null) && !open(e)).length;
    final theme = Theme.of(context);

    Widget action(IconData icon, String text, String button, VoidCallback? onPressed) => Padding(
          padding: const EdgeInsets.only(top: 6),
          child: Row(children: [
            Icon(icon, size: 18, color: color),
            const SizedBox(width: 8),
            Expanded(child: Text(text)),
            const SizedBox(width: 8),
            FilledButton.tonal(onPressed: onPressed, child: Text(button)),
          ]),
        );

    return Card(
      margin: EdgeInsets.zero,
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            SizedBox(
              width: 64,
              height: 64,
              child: Stack(alignment: Alignment.center, children: [
                CircularProgressIndicator(
                  value: score / 100,
                  strokeWidth: 7,
                  color: color,
                  backgroundColor: color.withValues(alpha: 0.15),
                ),
                Text('$score', style: theme.textTheme.titleLarge?.copyWith(color: color, fontWeight: FontWeight.bold)),
              ]),
            ),
            const SizedBox(width: 14),
            Expanded(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(grade, style: theme.textTheme.labelLarge?.copyWith(color: color)),
                Text(headline, style: theme.textTheme.titleMedium),
                Text(
                  events.isEmpty
                      ? 'Nothing captured yet. Start monitoring and use your device.'
                      : '${events.length} requests checked  |  $totalSent privacy-relevant sent  |  $stopped stopped by you',
                  style: theme.textTheme.bodySmall,
                ),
              ]),
            ),
          ]),
          if (events.isNotEmpty) ...[
            const Divider(height: 20),
            Text('Top findings', style: theme.textTheme.titleSmall),
            if (exposedList.isEmpty && openTrackerCats.isEmpty)
              const Padding(
                padding: EdgeInsets.only(top: 4),
                child: Text('No personal data or trackers are getting through right now.'),
              ),
            for (final x in exposedList.take(3))
              ListTile(
                dense: true,
                contentPadding: EdgeInsets.zero,
                leading: CircleAvatar(radius: 6, backgroundColor: severityColor(_Agg.worst(x.value))),
                title: Text('${x.key} received ${x.value.expand((e) => e.what.map((m) => m.category.label)).toSet().take(3).join(', ')}'),
                subtitle: Text('${_Agg.worst(x.value).label}  |  from ${x.value.map(_appName).toSet().join(', ')}  |  ${x.value.length} time(s)'),
                onTap: () => _show(x.key, (_, _) => _destDetail(x.key)),
              ),
            if (openTrackerCats.isNotEmpty)
              ListTile(
                dense: true,
                contentPadding: EdgeInsets.zero,
                leading: const CircleAvatar(radius: 6, backgroundColor: Colors.blue),
                title: Text('${openTrackerHosts.length} tracking destination(s) contacted'),
                subtitle: Text(openTrackerCats.join(', ')),
                onTap: () => _show('Behavioral tracking', _tracking),
              ),
            if (b != null && (exposedList.isNotEmpty || openTrackerCats.isNotEmpty)) ...[
              const Divider(height: 20),
              Text('Recommended actions', style: theme.textTheme.titleSmall),
              for (final x in exposedList.take(3))
                action(Icons.public_off, 'Stop sending data to ${x.key}', 'Block', () => setState(() => b.blockHost(x.key))),
              if (openTrackerCats.isNotEmpty)
                action(
                  Icons.visibility_off,
                  'Block ${openTrackerCats.length} tracker categor${openTrackerCats.length == 1 ? 'y' : 'ies'}. Safe for most sites, you will just see fewer ads.',
                  'Block all',
                  () => setState(() {
                    for (final c in openTrackerCats) {
                      _setCategoryBlocked(c, true);
                    }
                  }),
                ),
            ],
          ],
          if (b != null) ...[
            const Divider(height: 20),
            Row(children: [
              Icon(Icons.fact_check, size: 18, color: color),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  AuditStore.instance.snapshots.isEmpty
                      ? 'Audit: no snapshots yet. Take one to compare later.'
                      : 'Audit: ${AuditStore.instance.snapshots.length} snapshot(s), last ${_stamp(AuditStore.instance.snapshots.first.time)}',
                ),
              ),
              TextButton(onPressed: _openAuditList, child: const Text('Compare')),
              FilledButton(onPressed: _takeSnapshot, child: const Text('Snapshot')),
            ]),
          ],
        ]),
      ),
    );
  }

  void _openBlocked() async {
    final b = widget.blocker;
    if (b == null) return;
    await showDialog<void>(context: context, builder: (_) => BlockedAppsDialog(blocker: b));
    if (mounted) setState(() {});
  }

  Widget _blockedCard() {
    final b = widget.blocker;
    final hosts = b?.hosts.length ?? 0;
    final apps = b?.apps.length ?? 0;
    final refused = events.where(_isBlocked).length;
    return Card(
      margin: EdgeInsets.zero,
      clipBehavior: Clip.antiAlias,
      child: InkWell(
        onTap: b == null ? null : _openBlocked,
        child: Container(
          decoration: const BoxDecoration(border: Border(top: BorderSide(color: Colors.red, width: 4))),
          padding: const EdgeInsets.all(10),
          child: Row(children: [
            const Icon(Icons.block, color: Colors.red),
            const SizedBox(width: 10),
            Expanded(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text('Blocked', style: Theme.of(context).textTheme.titleSmall),
                Text('$hosts destination(s)${apps > 0 ? ', $apps app(s)' : ''} blocked  |  $refused request(s) refused this session'),
                Text('Tap to see everything blocked, grouped by type, and to unblock.',
                    style: Theme.of(context).textTheme.bodySmall),
              ]),
            ),
            const Icon(Icons.chevron_right, size: 18),
          ]),
        ),
      ),
    );
  }

  String _traffic(List<TransactionEvent> l) =>
      'up ${_bytes(_sum(l, (e) => e.bytesUp))}  down ${_bytes(_sum(l, (e) => e.bytesDown))}';

  /// Blocked requests are refused before any data moves, so this estimates what they would have
  /// transferred, using the average size of allowed requests to the same host (else overall).
  int _estimatedBlockedBytes() {
    final allowed = events.where((e) => !_isBlocked(e)).toList();
    if (allowed.isEmpty) return 0;
    int size(TransactionEvent e) => e.bytesUp + e.bytesDown;
    final overall = allowed.fold<int>(0, (n, e) => n + size(e)) ~/ allowed.length;
    final perHost = <String, List<int>>{};
    for (final e in allowed) {
      perHost.putIfAbsent(e.host, () => []).add(size(e));
    }
    var total = 0;
    for (final e in events.where(_isBlocked)) {
      final l = perHost[e.host];
      total += l == null ? overall : l.fold<int>(0, (n, x) => n + x) ~/ l.length;
    }
    return total;
  }

  Widget _trafficCard(_Agg a) {
    final up = _sum(events, (e) => e.bytesUp), down = _sum(events, (e) => e.bytesDown);
    final hosts = events.map((e) => e.host).toSet().length;
    final blockedBytes = _estimatedBlockedBytes();
    final blockedDest = widget.blocker?.hosts.length ?? 0;
    final blockedApps = widget.blocker?.apps.length ?? 0;
    Widget stat(IconData i, String value, String label) => Expanded(
          child: Column(children: [
            Icon(i, size: 20, color: Colors.indigo),
            Text(value, style: Theme.of(context).textTheme.titleMedium),
            Text(label, style: Theme.of(context).textTheme.bodySmall),
          ]),
        );
    return Card(
      margin: EdgeInsets.zero,
      clipBehavior: Clip.antiAlias,
      child: InkWell(
        onTap: () => _show('Monitored Privacy Traffic', _trafficDetail),
        child: Container(
          decoration: const BoxDecoration(border: Border(top: BorderSide(color: Colors.indigo, width: 4))),
          padding: const EdgeInsets.all(10),
          child: Column(children: [
            Row(children: [
              const Icon(Icons.swap_vert, size: 18, color: Colors.indigo),
              const SizedBox(width: 6),
              Expanded(child: Text('Monitored Privacy Traffic', style: Theme.of(context).textTheme.titleSmall)),
              const Icon(Icons.chevron_right, size: 18),
            ]),
            Align(
              alignment: Alignment.centerLeft,
              child: Text(
                'Web requests from apps using the PrivacyWatch proxy, the traffic that can carry personal data. Not all device traffic.',
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ),
            const SizedBox(height: 6),
            if (widget.dataDir != null) ...[
              TrafficTrendPanel(dataDir: widget.dataDir!, compact: true),
              const SizedBox(height: 6),
            ],
            Row(children: [
              stat(Icons.arrow_upward, _bytes(up), 'uploaded'),
              stat(Icons.arrow_downward, _bytes(down), 'downloaded'),
              stat(Icons.dns, '$hosts', 'destinations'),
              stat(Icons.computer, '${a.apps.length}', 'sources (apps)'),
            ]),
            const SizedBox(height: 8),
            Row(children: [
              stat(Icons.shield, blockedBytes == 0 ? '0 B' : '~${_bytes(blockedBytes)}', 'blocked (est.)'),
              stat(Icons.block, '$blockedDest', 'destinations blocked'),
              stat(Icons.apps, '$blockedApps', 'apps blocked'),
            ]),
          ]),
        ),
      ),
    );
  }

  Widget _trafficDetail(BuildContext ctx, VoidCallback _) {
    final byHost = <String, List<TransactionEvent>>{};
    for (final e in events) {
      byHost.putIfAbsent(e.host, () => []).add(e);
    }
    final hosts = byHost.entries.toList()
      ..sort((a, b) => _sum(b.value, (e) => e.bytesUp + e.bytesDown).compareTo(_sum(a.value, (e) => e.bytesUp + e.bytesDown)));
    final apps = _Agg(events).appList
      ..sort((a, b) => _sum(b.value, (e) => e.bytesUp + e.bytesDown).compareTo(_sum(a.value, (e) => e.bytesUp + e.bytesDown)));
    return ListView(shrinkWrap: true, children: [
      if (widget.dataDir != null) ...[
        Text('Trend over time', style: Theme.of(ctx).textTheme.titleSmall),
        const SizedBox(height: 4),
        TrafficTrendPanel(dataDir: widget.dataDir!),
        const SizedBox(height: 8),
      ],
      Text('Sources (apps)', style: Theme.of(ctx).textTheme.titleSmall),
      const SizedBox(height: 4),
      _table(
        first: 'App',
        rows: [
          for (final p in apps) _TableRow(p.key, p.value, () => _show(p.key, (_, _) => _appDetail(p.value))),
        ],
      ),
      const SizedBox(height: 12),
      Text('Destinations', style: Theme.of(ctx).textTheme.titleSmall),
      const SizedBox(height: 4),
      _table(
        first: 'Destination',
        rows: [
          for (final h in hosts) _TableRow(h.key, h.value, () => _show(h.key, (_, _) => _destDetail(h.key))),
        ],
      ),
    ]);
  }

  /// Compact table: one row per app or destination, sorted by the caller.
  Widget _table({required String first, required List<_TableRow> rows}) {
    final head = Theme.of(context).textTheme.labelMedium?.copyWith(fontWeight: FontWeight.bold);
    final cell = Theme.of(context).textTheme.bodySmall;
    Widget num(String t, {TextStyle? style}) => SizedBox(width: 62, child: Text(t, textAlign: TextAlign.right, style: style));
    Widget line(String name, String tx, String up, String down, String blocked,
        {TextStyle? style, VoidCallback? onTap, Color? color}) {
      return InkWell(
        onTap: onTap,
        child: Container(
          color: color,
          padding: const EdgeInsets.symmetric(vertical: 6, horizontal: 6),
          child: Row(children: [
            Expanded(child: Text(name, overflow: TextOverflow.ellipsis, style: style)),
            SizedBox(width: 34, child: Text(tx, textAlign: TextAlign.right, style: style)),
            num(up, style: style),
            num(down, style: style),
            SizedBox(width: 40, child: Text(blocked, textAlign: TextAlign.right, style: style)),
          ]),
        ),
      );
    }

    if (rows.isEmpty) return const Text('Nothing captured yet.');
    return Card(
      margin: EdgeInsets.zero,
      clipBehavior: Clip.antiAlias,
      child: Column(children: [
        line(first, 'Tx', 'Up', 'Down', 'Blkd', style: head, color: Theme.of(context).colorScheme.surfaceContainerHighest),
        for (var i = 0; i < rows.length; i++)
          line(
            rows[i].name,
            '${rows[i].events.length}',
            _bytes(_sum(rows[i].events, (e) => e.bytesUp)),
            _bytes(_sum(rows[i].events, (e) => e.bytesDown)),
            '${rows[i].events.where(_isBlocked).length}',
            style: cell,
            onTap: rows[i].onTap,
            color: i.isOdd ? Theme.of(context).colorScheme.surfaceContainerLow : null,
          ),
      ]),
    );
  }

  Widget _liveBanner() => ValueListenableBuilder<int>(
        valueListenable: widget.liveCount,
        builder: (_, _, _) {
          final fresh = widget.liveEvents.length - events.length;
          return Card(
            margin: EdgeInsets.zero,
            color: Theme.of(context).colorScheme.secondaryContainer,
            child: ListTile(
              dense: true,
              leading: const Icon(Icons.fiber_manual_record, color: Colors.red, size: 16),
              title: Text('${events.length} transactions captured'),
              subtitle: Text(fresh > 0 ? '$fresh new since opened. Capture keeps running.' : 'Up to date. Capture keeps running.'),
              trailing: TextButton(
                onPressed: fresh > 0 ? () => setState(() => events = List.of(widget.liveEvents)) : null,
                child: const Text('Refresh'),
              ),
            ),
          );
        },
      );

  // ---- pop-up plumbing ----

  /// Opens a phone-sized pop-up. [body] receives a rebuild callback so switches inside stay live.
  Future<void> _show(String title, Widget Function(BuildContext, VoidCallback) body,
      {List<Widget> actions = const []}) {
    return showDialog<void>(
      context: context,
      builder: (_) => Dialog(
        insetPadding: const EdgeInsets.all(12),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: _maxWidth, maxHeight: 640),
          child: StatefulBuilder(
            builder: (ctx, setLocal) => Column(mainAxisSize: MainAxisSize.min, children: [
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 8, 8, 0),
                child: Row(children: [
                  Expanded(child: Text(title, style: Theme.of(ctx).textTheme.titleMedium)),
                  ...actions,
                  IconButton(icon: const Icon(Icons.close), onPressed: () => Navigator.pop(ctx)),
                ]),
              ),
              const Divider(height: 1),
              Flexible(
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: body(ctx, () {
                    setLocal(() {});
                    setState(() {});
                  }),
                ),
              ),
            ]),
          ),
        ),
      ),
    );
  }

  void _copy(String text, String message) {
    Clipboard.setData(ClipboardData(text: text));
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(message)));
  }

  Widget _grid(List<Widget> tiles) => GridView.count(
        crossAxisCount: 2,
        shrinkWrap: true,
        mainAxisSpacing: 8,
        crossAxisSpacing: 8,
        childAspectRatio: 1.25,
        children: tiles,
      );

  // ---- card detail pop-ups ----

  Widget _personalData(BuildContext ctx, VoidCallback _) {
    final a = _Agg(events);
    if (a.cats.isEmpty) return const Center(child: Text('No personal data detected yet.'));
    return _grid([
      for (final c in a.cats)
        _Tile(
          badge: SeverityChip(c.severity),
          title: c.label,
          subtitle: '${a.byCategory[c]!.length} transaction(s)',
          onTap: () => _show(c.label, (_, _) => _finding(c, a.byCategory[c]!), actions: [
            IconButton(
              tooltip: 'Copy this finding',
              icon: const Icon(Icons.copy),
              onPressed: () => _copy(_findingText(c, a.byCategory[c]!), 'Finding copied'),
            ),
          ]),
        ),
    ]);
  }

  Widget _finding(PiiCategory c, List<TransactionEvent> list) => ListView(shrinkWrap: true, children: [
        Row(children: [SeverityChip(c.severity), const SizedBox(width: 8), Text('${list.length} transaction(s)')]),
        const SizedBox(height: 8),
        _section('What it is', c.explanation),
        _section('What it means for you', c.severity.guidance),
        _section('What to do', c.advice),
        const Divider(),
        Text('Occurrences', style: Theme.of(context).textTheme.titleSmall),
        for (final e in list) _txTile(e, only: c),
      ]);

  Widget _destinations(BuildContext ctx, VoidCallback _) {
    final a = _Agg(events);
    if (a.dests.isEmpty) return const Center(child: Text('No personal data has been sent anywhere yet.'));
    return _grid([
      for (final d in a.destList)
        _Tile(
          badge: SeverityChip(_Agg.worst(d.value)),
          title: d.key,
          subtitle: '${d.value.length} transaction(s)',
          onTap: () => _show(d.key, (_, _) => _destDetail(d.key)),
        ),
    ]);
  }

  Widget _tracking(BuildContext ctx, VoidCallback refresh) {
    final a = _Agg(events);
    // Always list every category so it can be blocked before any traffic is seen.
    final cats = [
      ...TrackerClassifier.categoryOrder,
      ...a.trackerCats.where((c) => !TrackerClassifier.categoryOrder.contains(c)),
    ];
    return ListView(shrinkWrap: true, children: [
      for (final cat in cats)
        Card(
          margin: const EdgeInsets.only(bottom: 8),
          clipBehavior: Clip.antiAlias,
          child: InkWell(
            onTap: () => _show(cat, (_, _) => _trackerCategory(cat)),
            child: Padding(
              padding: const EdgeInsets.all(10),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Row(children: [
                  const Icon(Icons.visibility, size: 18, color: Colors.blue),
                  const SizedBox(width: 6),
                  Expanded(
                    child: Text(
                        a.trackers[cat] == null ? '$cat  -  none seen yet' : '$cat  -  ${_blockedSummary(a.trackers[cat]!)}',
                        style: Theme.of(ctx).textTheme.titleSmall),
                  ),
                  if (widget.blocker != null)
                    Column(children: [
                      Switch(
                        value: _categoryBlocked(cat),
                        onChanged: (v) {
                          _setCategoryBlocked(cat, v);
                          refresh();
                        },
                      ),
                      Text(_categoryBlocked(cat) ? 'Blocked' : 'Turn off', style: const TextStyle(fontSize: 11)),
                    ]),
                ]),
                Text(TrackerClassifier.categoryShort[cat] ?? 'Collects data about your activity.',
                    style: const TextStyle(fontWeight: FontWeight.bold)),
                const SizedBox(height: 4),
                Text(TrackerClassifier.categoryInfo[cat] ?? '', style: Theme.of(ctx).textTheme.bodySmall),
                const SizedBox(height: 4),
                Text(
                  a.trackers[cat] == null
                      ? 'Nothing captured yet  -  ${TrackerClassifier.domainsFor(cat).length} known domains can be blocked'
                      : '${a.trackers[cat]!.map((e) => e.tracker!.owner).toSet().length} company(ies) | '
                          '${_traffic(a.trackers[cat]!)}  -  tap for details',
                  style: Theme.of(ctx).textTheme.labelSmall,
                ),
              ]),
            ),
          ),
        ),
    ]);
  }

  Widget _trackerCategory(String cat) {
    final list = _Agg(events).trackers[cat] ?? [];
    final owners = <String, List<TransactionEvent>>{};
    for (final e in list) {
      owners.putIfAbsent(e.tracker!.owner, () => []).add(e);
    }
    return ListView(shrinkWrap: true, children: [
      _section('What it is', TrackerClassifier.categoryInfo[cat] ?? 'Collects data about your activity.'),
      Text('${owners.length} company(ies), sent ${_bytes(_sum(list, (e) => e.bytesUp))}, '
          'received ${_bytes(_sum(list, (e) => e.bytesDown))}'),
      const Divider(),
      for (final o in owners.entries)
        ListTile(
          dense: true,
          title: Text('${o.key}  x${o.value.length}'),
          subtitle: Text('Contacted by: ${o.value.map(_appName).toSet().join(', ')}\n'
              'Hosts: ${o.value.map((e) => e.host).toSet().join(', ')}'),
        ),
    ]);
  }

  Widget _applications(BuildContext ctx, VoidCallback _) {
    final a = _Agg(events);
    if (a.apps.isEmpty) return const Center(child: Text('No traffic captured yet.'));
    return _grid([
      for (final p in a.appList)
        _Tile(
          badge: SeverityChip(_Agg.worst(p.value)),
          title: p.key,
          subtitle: '${p.value.length} tx | up ${_bytes(_sum(p.value, (e) => e.bytesUp))}\n'
              'down ${_bytes(_sum(p.value, (e) => e.bytesDown))} | ${p.value.map((e) => e.host).toSet().length} dest.',
          onTap: () => _show(p.key, (_, _) => _appDetail(p.value)),
        ),
    ]);
  }

  Widget _appDetail(List<TransactionEvent> appEvents) {
    final first = appEvents.first;
    final impact = AppImpact(_appName(first), first.appPath, appEvents);
    return ListView(shrinkWrap: true, children: [
      BlockDecisionPanel.app(blocker: widget.blocker, app: impact),
      Text('Transactions', style: Theme.of(context).textTheme.titleSmall),
      for (final e in appEvents.reversed) _txTile(e),
    ]);
  }

  Widget _destDetail(String host) {
    final impact = DestImpact(host, events);
    return ListView(shrinkWrap: true, children: [
      BlockDecisionPanel.destination(blocker: widget.blocker, dest: impact),
      Text('Transactions', style: Theme.of(context).textTheme.titleSmall),
      for (final e in impact.events.reversed) _txTile(e),
    ]);
  }

  /// Minimal view for one severity level: when, who, where, what, and whether it was stopped.
  Widget _severityList(BuildContext ctx, Severity s) {
    final list = events.where((e) => e.severity == s).toList()..sort((a, b) => b.time.compareTo(a.time));
    if (list.isEmpty) return Center(child: Text('Nothing at ${s.label} level.'));
    String hhmmss(DateTime t) =>
        '${t.hour.toString().padLeft(2, '0')}:${t.minute.toString().padLeft(2, '0')}:${t.second.toString().padLeft(2, '0')}';
    final small = Theme.of(ctx).textTheme.bodySmall;
    return ListView(shrinkWrap: true, children: [
      _section('What this level means', s.guidance),
      const Divider(),
      for (final e in list)
        ListTile(
          dense: true,
          contentPadding: EdgeInsets.zero,
          leading: Icon(_isBlocked(e) ? Icons.block : Icons.north_east,
              size: 18, color: _isBlocked(e) ? Colors.red : severityColor(s)),
          title: Text('${e.host}  |  ${_appName(e)}'),
          subtitle: Text(
            '${hhmmss(e.time)}  |  ${_isBlocked(e) ? 'BLOCKED - nothing sent' : 'SENT'}  |  '
            '${e.encrypted ? 'HTTPS' : 'HTTP, unencrypted'}\n'
            '${e.what.isNotEmpty ? e.what.map((m) => m.category.label).toSet().join(', ') : (e.tracker != null ? '${e.tracker!.category} (${e.tracker!.owner})' : 'No personal data')}',
            style: small,
          ),
          isThreeLine: true,
          onTap: () => _show(e.host, (_, _) => ListView(shrinkWrap: true, children: [_txTile(e)])),
        ),
    ]);
  }

  Widget _txTile(TransactionEvent e, {PiiCategory? only}) {
    final found = e.what.where((m) => only == null || m.category == only);
    return ListTile(
      dense: true,
      title: Text('${e.how} - ${e.destination}'),
      subtitle: Text([
        '${_appName(e)}  |  up ${_bytes(e.bytesUp)}, down ${_bytes(e.bytesDown)}',
        e.time.toIso8601String(),
        found.map((m) => '${m.category.label} in ${m.where} (${m.redacted})').join('; '),
        if (!e.encrypted) 'Sent unencrypted: anyone on the network path could read this.',
      ].where((s) => s.isNotEmpty).join('\n')),
    );
  }

  Widget _section(String head, String body) => Padding(
        padding: const EdgeInsets.only(bottom: 8),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(head, style: Theme.of(context).textTheme.labelLarge),
          Text(body),
        ]),
      );

  // ---- blocking by tracker category ----

  bool _categoryBlocked(String cat) {
    final b = widget.blocker;
    final domains = TrackerClassifier.domainsFor(cat);
    return b != null && domains.isNotEmpty && domains.every(b.isHostBlocked);
  }

  void _setCategoryBlocked(String cat, bool block) {
    final b = widget.blocker;
    if (b == null) return;
    for (final d in TrackerClassifier.domainsFor(cat)) {
      block ? b.blockHost(d) : b.unblockHost(d);
    }
  }

  // ---- copyable text ----

  String _findingText(PiiCategory c, List<TransactionEvent> list) {
    final b = StringBuffer()
      ..writeln('${c.severity.label.toUpperCase()}: ${c.label} (${list.length} transaction(s))')
      ..writeln('What it is: ${c.explanation}')
      ..writeln('What it means: ${c.severity.guidance}')
      ..writeln('What to do: ${c.advice}')
      ..writeln('Occurrences:');
    for (final e in list) {
      for (final m in e.what.where((m) => m.category == c)) {
        b.writeln('- ${e.time.toIso8601String()} | app: ${e.app ?? 'unknown'} | ${e.how} ${e.destination} '
            '| ${m.category.label} in ${m.where} (${m.redacted}) | ${e.encrypted ? 'encrypted' : 'UNENCRYPTED'} '
            '| up ${_bytes(e.bytesUp)}, down ${_bytes(e.bytesDown)}');
      }
    }
    return b.toString();
  }

  /// Plain-text report suitable for pasting into an email or an AI assistant for investigation.
  String _reportText(_Agg a) {
    final b = StringBuffer()
      ..writeln('PrivacyWatch report - generated ${DateTime.now().toIso8601String()}')
      ..writeln('${events.length} transactions captured. Values are redacted; HTTPS contents are not inspected.')
      ..writeln()
      ..writeln('=== PERSONAL DATA FINDINGS ===');
    if (a.cats.isEmpty) b.writeln('None detected.');
    for (final c in a.cats) {
      b.writeln(_findingText(c, a.byCategory[c]!));
    }
    b.writeln('=== BEHAVIORAL TRACKING (by category) ===');
    if (a.trackers.isEmpty) b.writeln('None detected.');
    for (final cat in a.trackerCats) {
      final list = a.trackers[cat]!;
      b.writeln('$cat: ${_blockedSummary(list)}');
      if (list.every(_isBlocked)) {
        b.writeln('  Status: already blocked by the user; these services received nothing.');
      } else {
        b.writeln('  ${TrackerClassifier.categoryInfo[cat] ?? ''}');
      }
      final owners = <String, Set<String>>{};
      for (final e in list) {
        owners.putIfAbsent(e.tracker!.owner, () => {}).add('${e.host} (${_appName(e)})');
      }
      for (final o in owners.entries) {
        b.writeln('  - ${o.key}: ${o.value.join(', ')}');
      }
    }
    b
      ..writeln()
      ..writeln('=== MONITORED PRIVACY TRAFFIC (web requests through the PrivacyWatch proxy, not all device traffic) ===')
      ..writeln('Uploaded ${_bytes(_sum(events, (e) => e.bytesUp))}, downloaded ${_bytes(_sum(events, (e) => e.bytesDown))}, '
          '${events.map((e) => e.host).toSet().length} destination(s), ${a.apps.length} source app(s)')
      ..writeln()
      ..writeln('=== APPLICATIONS ===');
    for (final p in a.appList) {
      b.writeln('${p.key}: ${p.value.length} transaction(s) (${p.value.where(_isBlocked).length} blocked), '
          'up ${_bytes(_sum(p.value, (e) => e.bytesUp))}, '
          'down ${_bytes(_sum(p.value, (e) => e.bytesDown))}, ${p.value.map((e) => e.host).toSet().length} destination(s)');
    }
    return b.toString();
  }
}

class _QuadCard extends StatelessWidget {
  const _QuadCard({
    required this.icon,
    required this.title,
    required this.big,
    required this.unit,
    required this.color,
    required this.lines,
    required this.onTap,
    this.traffic,
  });
  final IconData icon;
  final String title, big, unit;
  final String? traffic; // total up/down for the events behind this card
  final Color color;
  final List<String> lines;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) => Card(
        clipBehavior: Clip.antiAlias,
        margin: EdgeInsets.zero,
        child: InkWell(
          onTap: onTap,
          child: Container(
            decoration: BoxDecoration(border: Border(top: BorderSide(color: color, width: 4))),
            padding: const EdgeInsets.all(10),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Row(children: [
                Icon(icon, size: 18, color: color),
                const SizedBox(width: 6),
                Expanded(
                  child: Text(title,
                      maxLines: 1, overflow: TextOverflow.ellipsis, style: Theme.of(context).textTheme.titleSmall),
                ),
              ]),
              const SizedBox(height: 4),
              Text(big, style: Theme.of(context).textTheme.headlineMedium?.copyWith(color: color)),
              Text(unit, style: Theme.of(context).textTheme.bodySmall),
              const Divider(height: 12),
              for (final l in lines.take(2))
                Text(l, maxLines: 1, overflow: TextOverflow.ellipsis, style: Theme.of(context).textTheme.bodySmall),
              const Spacer(),
              if (traffic != null)
                Row(children: [
                  const Icon(Icons.swap_vert, size: 14),
                  const SizedBox(width: 4),
                  Expanded(
                    child: Text(traffic!,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: Theme.of(context).textTheme.labelSmall?.copyWith(fontWeight: FontWeight.bold)),
                  ),
                  const Icon(Icons.chevron_right, size: 18),
                ])
              else
                const Align(alignment: Alignment.bottomRight, child: Icon(Icons.chevron_right, size: 18)),
            ]),
          ),
        ),
      );
}

class _Tile extends StatelessWidget {
  const _Tile({required this.title, required this.subtitle, required this.onTap, this.badge});
  final String title, subtitle;
  final Widget? badge;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) => Card(
        margin: EdgeInsets.zero,
        clipBehavior: Clip.antiAlias,
        child: InkWell(
          onTap: onTap,
          child: Padding(
            padding: const EdgeInsets.all(8),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              ?badge,
              Text(title, maxLines: 2, overflow: TextOverflow.ellipsis, style: Theme.of(context).textTheme.titleSmall),
              Expanded(
                child: Text(subtitle,
                    maxLines: 3, overflow: TextOverflow.ellipsis, style: Theme.of(context).textTheme.bodySmall),
              ),
            ]),
          ),
        ),
      );
}
