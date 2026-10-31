import 'package:flutter/material.dart';

import 'core/audit_store.dart';

String _two(int n) => n.toString().padLeft(2, '0');
String stampOf(DateTime t) => '${t.year}-${_two(t.month)}-${_two(t.day)} ${_two(t.hour)}:${_two(t.minute)}';

String _detail(AuditItem i) {
  final p = [if (i.category != null) i.category!, if (i.owner != null) i.owner!, if (i.severity != null) i.severity!];
  return p.join(', ');
}

class _Group {
  const _Group(this.title, this.items, this.color, this.icon);
  final String title;
  final List<AuditItem> items;
  final Color color;
  final IconData icon;
}

/// Worse things first, then better, then unchanged.
List<_Group> _exposures(AuditDiff d) => [
      _Group('New and getting through', d.newlySeenOpen, Colors.red.shade700, Icons.warning_amber),
      _Group('Unblocked since', d.newlyUnblocked, Colors.orange.shade800, Icons.lock_open),
    ];
List<_Group> _improvements(AuditDiff d) => [
      _Group('Blocked since', d.newlyBlocked, Colors.green.shade700, Icons.block),
      _Group('New but already blocked', d.newlySeenBlocked, Colors.green.shade700, Icons.shield),
    ];
List<_Group> _unchanged(AuditDiff d) => [
      _Group('Still getting through', d.stillOpen, Colors.amber.shade800, Icons.error_outline),
      _Group('Still blocked', d.stillBlocked, Colors.blueGrey, Icons.shield_outlined),
      _Group('Not seen again', d.notSeenAgain, Colors.grey, Icons.visibility_off),
    ];

int _count(List<_Group> g) => g.fold(0, (n, x) => n + x.items.length);

String auditDiffText(AuditDiff d) {
  final b = StringBuffer()
    ..writeln('PrivacyWatch audit: ${d.earlier.id} (${stampOf(d.earlier.time)}) -> ${d.later.id} (${stampOf(d.later.time)})')
    ..writeln('Score ${d.earlier.score} -> ${d.later.score} (${d.scoreChange >= 0 ? '+' : ''}${d.scoreChange})')
    ..writeln();
  void section(String name, List<_Group> groups) {
    b.writeln('$name (${_count(groups)})');
    for (final g in groups) {
      for (final i in g.items) {
        final x = _detail(i);
        b.writeln('- ${g.title}: ${i.host}${x.isEmpty ? '' : ' ($x)'}');
      }
    }
    b.writeln();
  }

  section('NEW EXPOSURES', _exposures(d));
  section('IMPROVEMENTS', _improvements(d));
  section('NO CHANGE', _unchanged(d));
  b.writeln('Based on traffic captured while the app was open; HTTPS contents are not inspected.');
  return b.toString();
}

/// Saved snapshots with an automatic comparison. The app works out which is older and which is newer.
class AuditView extends StatefulWidget {
  const AuditView({super.key, required this.live, required this.onCopy, required this.onSnapshot, required this.onChanged});
  final AuditSnapshot Function() live;
  final void Function(String) onCopy;
  final VoidCallback onSnapshot;
  final VoidCallback onChanged;

  @override
  State<AuditView> createState() => _AuditViewState();
}

class _AuditViewState extends State<AuditView> {
  // Snapshot ids the user ticked; empty means "latest snapshot versus right now".
  final _picked = <String>[];

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final snaps = AuditStore.instance.snapshots; // newest first
    _picked.removeWhere((id) => !snaps.any((s) => s.id == id));

    final live = widget.live();
    AuditSnapshot? a, b;
    String basis = '';
    if (snaps.isNotEmpty) {
      if (_picked.length >= 2) {
        final two = snaps.where((s) => _picked.contains(s.id)).toList()..sort((x, y) => x.time.compareTo(y.time));
        a = two.first;
        b = two.last;
        basis = 'Comparing the two snapshots you selected';
      } else if (_picked.length == 1) {
        a = snaps.firstWhere((s) => s.id == _picked.first);
        b = live;
        basis = 'Comparing ${a.id} with right now';
      } else if (live.items.isNotEmpty && _signature(snaps.first) != _signature(live)) {
        a = snaps.first;
        b = live;
        basis = 'Changes since your last snapshot';
      } else {
        // Nothing new since the last snapshot: use the most recent earlier one that actually differed.
        final prev = snaps.skip(1).where((s) => _signature(s) != _signature(snaps.first));
        if (prev.isNotEmpty) {
          a = prev.first;
          b = snaps.first;
          basis = 'Changes between your last two different snapshots';
        } else {
          a = snaps.first;
          b = live;
          basis = snaps.length > 1 ? 'No change in any snapshot or since' : 'Nothing has changed since your snapshot';
        }
      }
    }
    final diff = (a != null && b != null) ? AuditDiff(a, b) : null;

    return ListView(shrinkWrap: true, children: [
      Text(
        'A snapshot is your privacy state at one moment. The app compares them for you and shows what got better or worse. '
        'Snapshots stay inside the app and survive restarts.',
        style: t.bodySmall,
      ),
      const SizedBox(height: 8),
      Row(children: [
        FilledButton.icon(onPressed: widget.onSnapshot, icon: const Icon(Icons.camera_alt), label: const Text('Take snapshot now')),
        const Spacer(),
        if (snaps.isNotEmpty)
          TextButton.icon(
            onPressed: () {
              AuditStore.instance.clearAll();
              setState(_picked.clear);
              widget.onChanged();
            },
            icon: const Icon(Icons.delete_sweep),
            label: const Text('Delete all'),
          ),
      ]),
      if (snaps.isEmpty)
        const Padding(padding: EdgeInsets.all(12), child: Text('No snapshots yet. Take one now, then take another after you make changes.'))
      else ...[
        const SizedBox(height: 6),
        if (diff != null) _result(diff, basis, t),
        const Divider(),
        Text('History', style: t.titleSmall),
        for (var i = 0; i < snaps.length; i++)
          ListTile(
            dense: true,
            contentPadding: EdgeInsets.zero,
            leading: const Icon(Icons.fact_check),
            title: Text('${stampOf(snaps[i].time)}   score ${snaps[i].score}'),
            subtitle: Text(
              i == snaps.length - 1
                  ? 'First snapshot  |  ${snaps[i].items.length} destinations, ${snaps[i].items.where((x) => x.blocked).length} blocked'
                  : _delta(snaps[i + 1], snaps[i]),
            ),
          ),
        ExpansionTile(
          tilePadding: EdgeInsets.zero,
          dense: true,
          title: const Text('Compare a different pair (optional)'),
          subtitle: const Text('Tick one to compare with now, or two to compare with each other.'),
          children: [
        for (final s in snaps)
          CheckboxListTile(
            dense: true,
            contentPadding: EdgeInsets.zero,
            controlAffinity: ListTileControlAffinity.leading,
            value: _picked.contains(s.id),
            onChanged: (v) => setState(() {
              if (v == true) {
                _picked.add(s.id);
                if (_picked.length > 2) _picked.removeAt(0);
              } else {
                _picked.remove(s.id);
              }
            }),
            title: Text('${stampOf(s.time)}   score ${s.score}'),
            subtitle: Text('${s.id}  |  ${s.items.length} destinations  |  ${s.blockedDestinations} blocked'),
            secondary: IconButton(
              icon: const Icon(Icons.delete_outline),
              tooltip: 'Delete',
              onPressed: () {
                AuditStore.instance.delete(s.id);
                setState(() {});
                widget.onChanged();
              },
            ),
          ),
          ],
        ),
      ],
    ]);
  }

  /// What matters for a comparison: the score and which destinations are blocked.
  static String _signature(AuditSnapshot s) {
    final items = [for (final i in s.items) '${i.host}:${i.blocked ? 1 : 0}']..sort();
    return '${s.score}|${items.join(',')}';
  }

  static String _delta(AuditSnapshot earlier, AuditSnapshot later) {
    final d = AuditDiff(earlier, later);
    final parts = [
      if (d.newlyBlocked.isNotEmpty) '${d.newlyBlocked.length} blocked',
      if (d.newlyUnblocked.isNotEmpty) '${d.newlyUnblocked.length} unblocked',
      if (d.newlySeenOpen.isNotEmpty) '${d.newlySeenOpen.length} new exposed',
      if (d.newlySeenBlocked.isNotEmpty) '${d.newlySeenBlocked.length} new blocked',
    ];
    final s = d.scoreChange == 0 ? 'score unchanged' : 'score ${d.scoreChange > 0 ? '+' : ''}${d.scoreChange}';
    return parts.isEmpty ? 'No change  |  $s' : '${parts.join(', ')}  |  $s';
  }

  Widget _result(AuditDiff d, String basis, TextTheme t) {
    final exposures = _exposures(d);
    final improvements = _improvements(d);
    final unchanged = _unchanged(d);
    final nBad = _count(exposures);
    final nGood = _count(improvements);
    final (Color c, IconData icon, String verdict) = d.scoreChange > 0 || (d.scoreChange == 0 && nGood > nBad)
        ? (Colors.green.shade700, Icons.trending_up, 'Improved')
        : d.scoreChange < 0 || nBad > 0
            ? (Colors.red.shade800, Icons.trending_down, 'More exposed')
            : (Colors.blueGrey, Icons.trending_flat, 'No change');

    Widget section(String title, Color color, List<_Group> groups, {bool open = true}) {
      final n = _count(groups);
      return ExpansionTile(
        initiallyExpanded: open && n > 0,
        tilePadding: EdgeInsets.zero,
        dense: true,
        title: Text('$title ($n)', style: t.titleSmall?.copyWith(color: color)),
        children: [
          if (n == 0) const Align(alignment: Alignment.centerLeft, child: Padding(padding: EdgeInsets.only(bottom: 8), child: Text('None'))),
          for (final g in groups)
            for (final i in g.items)
              ListTile(
                dense: true,
                contentPadding: EdgeInsets.zero,
                leading: Icon(g.icon, color: g.color, size: 20),
                title: Text(i.host),
                subtitle: Text([g.title, _detail(i)].where((s) => s.isNotEmpty).join('  |  ')),
              ),
        ],
      );
    }

    return Card(
      margin: EdgeInsets.zero,
      color: c.withValues(alpha: 0.07),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            Icon(icon, color: c, size: 30),
            const SizedBox(width: 10),
            Expanded(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(verdict, style: t.titleMedium?.copyWith(color: c, fontWeight: FontWeight.bold)),
                Text(
                  'Score ${d.earlier.score} -> ${d.later.score}'
                  '${d.scoreChange == 0 ? '' : ' (${d.scoreChange > 0 ? '+' : ''}${d.scoreChange})'}',
                ),
              ]),
            ),
            TextButton.icon(onPressed: () => widget.onCopy(auditDiffText(d)), icon: const Icon(Icons.copy), label: const Text('Copy')),
          ]),
          Text('$basis: ${stampOf(d.earlier.time)} -> ${d.later.id == 'Now (live)' ? 'now' : stampOf(d.later.time)}', style: t.bodySmall),
          const SizedBox(height: 4),
          section('New exposures', Colors.red.shade800, exposures),
          section('Improvements', Colors.green.shade700, improvements),
          section('No change', Colors.blueGrey, unchanged, open: false),
        ]),
      ),
    );
  }
}
