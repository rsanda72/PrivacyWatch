import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'core/app_blocker.dart';
import 'core/event.dart';
import 'core/pii_detector.dart';
import 'core/tracker_classifier.dart';

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
  const ReportPage({super.key, required this.liveEvents, required this.liveCount, this.blocker});
  final List<TransactionEvent> liveEvents; // still receiving captures while the report is open
  final ValueListenable<int> liveCount;
  final AppBlocker? blocker;

  @override
  State<ReportPage> createState() => _ReportPageState();
}

String _appName(TransactionEvent e) =>
    (e.app ?? 'unknown app').replaceAll(RegExp(r' \(PID \d+\)'), '');

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
      ]),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: _maxWidth),
          child: ListView(padding: const EdgeInsets.all(12), children: [
            _liveBanner(),
            const SizedBox(height: 8),
            Wrap(spacing: 6, runSpacing: 0, alignment: WrapAlignment.center, children: [
              for (final s in Severity.values.reversed)
                Chip(
                  visualDensity: VisualDensity.compact,
                  avatar: CircleAvatar(backgroundColor: severityColor(s), radius: 6),
                  label: Text('${s.label} ${a.bySeverity[s]}', style: const TextStyle(fontSize: 12)),
                ),
            ]),
            const SizedBox(height: 8),
            GridView.count(
              crossAxisCount: 2,
              shrinkWrap: true,
              physics: const NeverScrollableScrollPhysics(),
              mainAxisSpacing: 10,
              crossAxisSpacing: 10,
              childAspectRatio: 1.4,
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
                  unit: 'tracker contact(s)',
                  color: a.trackers.isEmpty ? Colors.green : Colors.blue,
                  lines: [
                    if (a.trackers.isEmpty) 'None detected yet',
                    for (final c in a.trackerCats.take(2)) '$c (${a.trackers[c]!.length})',
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
            _trafficCard(a),
            const SizedBox(height: 8),
            Text(
              'Tap a card for details. Severity is based on the data type; plain HTTP is raised one level because it is '
              'unencrypted. HTTPS contents are not decrypted, so they are not analysed.',
              style: Theme.of(context).textTheme.bodySmall,
              textAlign: TextAlign.center,
            ),
          ]),
        ),
      ),
    );
  }

  String _traffic(List<TransactionEvent> l) =>
      'up ${_bytes(_sum(l, (e) => e.bytesUp))}  down ${_bytes(_sum(l, (e) => e.bytesDown))}';

  Widget _trafficCard(_Agg a) {
    final up = _sum(events, (e) => e.bytesUp), down = _sum(events, (e) => e.bytesDown);
    final hosts = events.map((e) => e.host).toSet().length;
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
        onTap: () => _show('Traffic', _trafficDetail),
        child: Container(
          decoration: const BoxDecoration(border: Border(top: BorderSide(color: Colors.indigo, width: 4))),
          padding: const EdgeInsets.all(10),
          child: Column(children: [
            Row(children: [
              const Icon(Icons.swap_vert, size: 18, color: Colors.indigo),
              const SizedBox(width: 6),
              Expanded(child: Text('Traffic', style: Theme.of(context).textTheme.titleSmall)),
              const Icon(Icons.chevron_right, size: 18),
            ]),
            const SizedBox(height: 6),
            Row(children: [
              stat(Icons.arrow_upward, _bytes(up), 'uploaded'),
              stat(Icons.arrow_downward, _bytes(down), 'downloaded'),
              stat(Icons.dns, '$hosts', 'destinations'),
              stat(Icons.computer, '${a.apps.length}', 'sources (apps)'),
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
      Text('Sources (apps)', style: Theme.of(ctx).textTheme.titleSmall),
      const SizedBox(height: 4),
      _grid([
        for (final p in apps)
          _Tile(
            title: p.key,
            subtitle: '${_traffic(p.value)}\n${p.value.map((e) => e.host).toSet().length} destination(s)',
            onTap: () => _show(p.key, (_, _) => _txList(p.value)),
          ),
      ]),
      const SizedBox(height: 8),
      Text('Destinations', style: Theme.of(ctx).textTheme.titleSmall),
      const SizedBox(height: 4),
      _grid([
        for (final h in hosts)
          _Tile(
            title: h.key,
            subtitle: '${_traffic(h.value)}\n${h.value.length} transaction(s)',
            onTap: () => _show(h.key, (_, _) => _txList(h.value)),
          ),
      ]),
    ]);
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
          onTap: () => _show(d.key, (_, _) => _txList(d.value)),
        ),
    ]);
  }

  Widget _tracking(BuildContext ctx, VoidCallback refresh) {
    final a = _Agg(events);
    if (a.trackers.isEmpty) return const Center(child: Text('No known trackers contacted yet.'));
    return _grid([
      for (final cat in a.trackerCats)
        _Tile(
          badge: widget.blocker == null
              ? null
              : Row(mainAxisSize: MainAxisSize.min, children: [
                  Switch(
                    value: _categoryBlocked(cat),
                    onChanged: (v) {
                      _setCategoryBlocked(cat, v);
                      refresh();
                    },
                  ),
                  Text(_categoryBlocked(cat) ? 'Blocked' : 'Turn off', style: const TextStyle(fontSize: 11)),
                ]),
          title: cat,
          subtitle: '${a.trackers[cat]!.length} contact(s)',
          onTap: () => _show(cat, (_, rebuild) => _trackerCategory(cat), actions: []),
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
          onTap: () => _show(p.key, (_, _) => _txList(p.value)),
        ),
    ]);
  }

  Widget _txList(List<TransactionEvent> list) =>
      ListView(shrinkWrap: true, children: [for (final e in list.reversed) _txTile(e)]);

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
      b.writeln('$cat: ${list.length} transaction(s)');
      b.writeln('  ${TrackerClassifier.categoryInfo[cat] ?? ''}');
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
      ..writeln('=== TRAFFIC ===')
      ..writeln('Uploaded ${_bytes(_sum(events, (e) => e.bytesUp))}, downloaded ${_bytes(_sum(events, (e) => e.bytesDown))}, '
          '${events.map((e) => e.host).toSet().length} destination(s), ${a.apps.length} source app(s)')
      ..writeln()
      ..writeln('=== APPLICATIONS ===');
    for (final p in a.appList) {
      b.writeln('${p.key}: ${p.value.length} transaction(s), up ${_bytes(_sum(p.value, (e) => e.bytesUp))}, '
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
