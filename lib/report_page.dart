import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

import 'core/event.dart';
import 'core/pii_detector.dart';

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

class ReportPage extends StatefulWidget {
  const ReportPage({super.key, required this.liveEvents, required this.liveCount});
  final List<TransactionEvent> liveEvents; // still receiving captures while the report is open
  final ValueListenable<int> liveCount;

  @override
  State<ReportPage> createState() => _ReportPageState();
}

class _ReportPageState extends State<ReportPage> {
  late List<TransactionEvent> events = List.of(widget.liveEvents);

  @override
  Widget build(BuildContext context) {
    final bySeverity = {for (final s in Severity.values) s: 0};
    final byCategory = <PiiCategory, List<TransactionEvent>>{};
    final byDest = <String, List<TransactionEvent>>{};
    final apps = <String, List<TransactionEvent>>{};
    final trackers = <String, List<TransactionEvent>>{};
    for (final e in events) {
      bySeverity[e.severity] = bySeverity[e.severity]! + 1;
      apps.putIfAbsent((e.app ?? 'unknown app').replaceAll(RegExp(r' \(PID \d+\)'), ''), () => []).add(e);
      final t = e.tracker;
      if (t != null) trackers.putIfAbsent('${t.owner} - ${t.category}', () => []).add(e);
      if (e.what.isEmpty) continue;
      byDest.putIfAbsent(e.who.split(' | ').first, () => []).add(e);
      for (final c in e.what.map((m) => m.category).toSet()) {
        byCategory.putIfAbsent(c, () => []).add(e);
      }
    }
    final cats = byCategory.keys.toList()
      ..sort((a, b) => b.severity.rank.compareTo(a.severity.rank));
    final dests = byDest.entries.toList()
      ..sort((a, b) => _worst(b.value).rank.compareTo(_worst(a.value).rank));

    return Scaffold(
      appBar: AppBar(title: const Text('Report / Analysis')),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        ValueListenableBuilder<int>(
          valueListenable: widget.liveCount,
          builder: (_, _, _) {
            final fresh = widget.liveEvents.length - events.length;
            return Card(
              color: Theme.of(context).colorScheme.secondaryContainer,
              child: ListTile(
                leading: const Icon(Icons.fiber_manual_record, color: Colors.red),
                title: const Text('Capture is still running in the background.'),
                subtitle: Text(fresh > 0
                    ? '$fresh new transaction(s) since this report was opened.'
                    : 'This report is up to date.'),
                trailing: TextButton(
                  onPressed: fresh > 0 ? () => setState(() => events = List.of(widget.liveEvents)) : null,
                  child: const Text('Refresh'),
                ),
              ),
            );
          },
        ),
        Text('${events.length} transactions captured', style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 8),
        Wrap(spacing: 8, runSpacing: 4, children: [
          for (final s in Severity.values.reversed)
            Chip(
              avatar: CircleAvatar(backgroundColor: severityColor(s), radius: 6),
              label: Text('${s.label}: ${bySeverity[s]}'),
            ),
        ]),
        const SizedBox(height: 16),
        Text('Personal data found', style: Theme.of(context).textTheme.titleMedium),
        if (cats.isEmpty) const ListTile(title: Text('No personal data detected yet.')),
        for (final c in cats)
          Card(
            child: ListTile(
              leading: SeverityChip(c.severity),
              title: Text('${c.label}  x${byCategory[c]!.length}'),
              subtitle: Text(c.explanation),
            ),
          ),
        const SizedBox(height: 16),
        Text('Who received it', style: Theme.of(context).textTheme.titleMedium),
        for (final d in dests)
          ExpansionTile(
            leading: SeverityChip(_worst(d.value)),
            title: Text(d.key),
            subtitle: Text('${d.value.length} transaction(s)'),
            children: [
              for (final e in d.value)
                ListTile(
                  dense: true,
                  title: Text('${e.how} - ${e.destination}'),
                  subtitle: Text([
                    '${e.app ?? 'unknown app'}  |  up ${TransactionEvent.formatBytes(e.bytesUp)}, down ${TransactionEvent.formatBytes(e.bytesDown)}',
                    e.time.toIso8601String(),
                    e.what.map((m) => '${m.category.label} in ${m.where} (${m.redacted})').join('; '),
                    if (!e.encrypted) 'Sent unencrypted: anyone on the network path could read this.',
                  ].join('\n')),
                ),
            ],
          ),
        const SizedBox(height: 16),
        Text('Behavioral tracking (no personal data needed)', style: Theme.of(context).textTheme.titleMedium),
        if (trackers.isEmpty) const ListTile(title: Text('No known trackers contacted yet.')),
        for (final t in trackers.entries)
          Card(
            child: ListTile(
              leading: const Icon(Icons.visibility),
              title: Text('${t.key}  x${t.value.length}'),
              subtitle: Text(
                'Contacted by: ${t.value.map((e) => e.app ?? 'unknown app').toSet().join(', ')}\n'
                'Sent ${TransactionEvent.formatBytes(_sum(t.value, (e) => e.bytesUp))}, '
                'received ${TransactionEvent.formatBytes(_sum(t.value, (e) => e.bytesDown))}. '
                'Analytics, ad and telemetry services build a profile of what you do and when.',
              ),
            ),
          ),
        const SizedBox(height: 16),
        Text('Applications and data volume', style: Theme.of(context).textTheme.titleMedium),
        for (final a in apps.entries)
          ListTile(
            leading: const Icon(Icons.apps),
            title: Text(a.key),
            subtitle: Text('${a.value.length} transactions  |  '
                'up ${TransactionEvent.formatBytes(_sum(a.value, (e) => e.bytesUp))}, '
                'down ${TransactionEvent.formatBytes(_sum(a.value, (e) => e.bytesDown))}  |  '
                '${a.value.map((e) => e.host).toSet().length} destinations'),
          ),
        const SizedBox(height: 16),
        const Text(
          'Severity is based on the data type; plain-HTTP transfers are raised one level because they are unencrypted. '
          'HTTPS traffic is not decrypted, so its contents are not analysed.',
          style: TextStyle(fontSize: 12),
        ),
      ]),
    );
  }

  int _sum(List<TransactionEvent> l, int Function(TransactionEvent) f) => l.fold(0, (a, e) => a + f(e));

  Severity _worst(List<TransactionEvent> l) =>
      l.map((e) => e.severity).reduce((a, b) => a.rank >= b.rank ? a : b);
}
