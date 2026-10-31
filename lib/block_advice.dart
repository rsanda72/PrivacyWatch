import 'package:flutter/material.dart';

import 'core/app_blocker.dart';
import 'core/event.dart';

/// General-purpose programs: many unrelated things use them, so blocking the whole program breaks legitimate use.
const _sharedPrograms = {
  'curl.exe', 'wget.exe', 'powershell.exe', 'pwsh.exe', 'cmd.exe', 'python.exe', 'pythonw.exe', 'node.exe',
  'java.exe', 'javaw.exe', 'chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe', 'opera.exe', 'svchost.exe',
  'explorer.exe', 'git.exe', 'ssh.exe',
};

bool _concerning(TransactionEvent e) => e.what.isNotEmpty || e.tracker != null;
String _bytes(int b) => TransactionEvent.formatBytes(b);

/// What blocking a program would cost, based on the traffic seen so far.
class AppImpact {
  AppImpact(this.name, this.path, this.events) {
    for (final e in events) {
      hosts.add(e.host);
      if (_concerning(e)) {
        concernHosts.add(e.host);
        concernTx++;
      }
    }
  }

  final String name;
  final String? path;
  final List<TransactionEvent> events;
  final hosts = <String>{};
  final concernHosts = <String>{};
  int concernTx = 0;

  Set<String> get cleanHosts => hosts.difference(concernHosts);
  int get cleanTx => events.length - concernTx;

  String? get sharedReason {
    if (_sharedPrograms.contains(name.toLowerCase())) return '$name is a general-purpose program used by many things';
    if (hosts.length >= 8) return '$name talks to ${hosts.length} different destinations';
    if ((path ?? '').toLowerCase().startsWith(r'c:\windows\')) return '$name is part of Windows';
    return null;
  }

  bool get preferApp => sharedReason == null && concernHosts.isNotEmpty && (cleanHosts.isEmpty || concernTx * 2 > events.length);

  String get recommendation {
    if (concernHosts.isEmpty) return 'Nothing concerning was seen from $name, so no block is needed.';
    if (preferApp) {
      return 'Recommended: block the app. ${cleanHosts.isEmpty ? 'Everything' : 'Most'} we saw it send went to destinations of '
          'concern ($concernTx of ${events.length} transactions), so blocking it costs little.';
    }
    final why = sharedReason;
    if (why != null) {
      return 'Recommended: block the destination(s), not the app. $why, so blocking it would also cut off its '
          '${cleanHosts.length} normal destination(s) and everything else that uses it.';
    }
    return 'Recommended: block the ${concernHosts.length} concerning destination(s). $name also made $cleanTx normal '
        'transaction(s) that you would lose if you blocked the whole app.';
  }

  List<String> get impactLines => [
        'Block the app: stops all ${hosts.length} destination(s) it contacted (${events.length} transaction(s), '
            'up ${_bytes(events.fold(0, (a, e) => a + e.bytesUp))}, down ${_bytes(events.fold(0, (a, e) => a + e.bytesDown))}).',
        if (concernHosts.isNotEmpty)
          'Block only the concerning destinations: stops ${concernHosts.length} (${concernHosts.take(3).join(', ')}'
              '${concernHosts.length > 3 ? ', ...' : ''}) and keeps ${cleanHosts.length} normal destination(s) working.',
      ];
}

/// What blocking a destination would cost, based on the traffic seen so far.
class DestImpact {
  DestImpact(this.host, List<TransactionEvent> all)
      : events = all.where((e) => e.host == host || e.host.endsWith('.$host')).toList() {
    for (final e in events) {
      apps.add(e.appName ?? 'unknown app');
      if (e.what.isNotEmpty) piiTx++;
      trackerCategory ??= e.tracker?.category;
    }
  }

  final String host;
  final List<TransactionEvent> events;
  final apps = <String>{};
  int piiTx = 0;
  String? trackerCategory;

  String get recommendation {
    if (trackerCategory != null) {
      return 'Safe to block: this is a $trackerCategory service. It exists to collect behavioral data, and sites and apps '
          'normally work without it.';
    }
    if (piiTx > 0) {
      return 'Block it if you do not recognize this recipient. If it is a service you use on purpose (bank, shop, sign-in), '
          'blocking it breaks that service for all ${apps.length} app(s) that use it.';
    }
    return 'No personal data or tracking was seen going here. Block it only if you do not trust the destination.';
  }

  List<String> get impactLines => [
        'Block the destination: $host and its subdomains stop working for every app using the proxy '
            '(${apps.length} app(s) used it: ${apps.take(3).join(', ')}${apps.length > 3 ? ', ...' : ''}).',
        'The apps themselves keep working for all other destinations.',
      ];
}

/// Side-by-side explanation of the two blocking choices.
class BlockingGuide extends StatelessWidget {
  const BlockingGuide({super.key});

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    Widget col(IconData icon, String head, List<String> lines) => Expanded(
          child: Container(
            margin: const EdgeInsets.symmetric(horizontal: 3),
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              border: Border.all(color: Theme.of(context).dividerColor),
              borderRadius: BorderRadius.circular(6),
            ),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Row(children: [
                Icon(icon, size: 16),
                const SizedBox(width: 4),
                Expanded(child: Text(head, style: t.labelLarge)),
              ]),
              for (final l in lines)
                Padding(padding: const EdgeInsets.only(top: 4), child: Text(l, style: t.bodySmall)),
            ]),
          ),
        );
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        col(Icons.public_off, 'Block destination', const [
          'Scope: one site and its subdomains, for every app.',
          'The app keeps working everywhere else.',
          'No admin permission needed.',
          'Best for: trackers, an unfamiliar recipient, or shared programs (browser, curl, PowerShell, Windows).',
        ]),
        col(Icons.block, 'Block app', const [
          'Scope: the whole program, every destination.',
          'It loses all network use (updates, sign-in, sync) until unblocked. A shared program breaks for everything.',
          'Windows asks for permission.',
          'Best for: an unknown or untrusted program.',
        ]),
      ]),
      const SizedBox(height: 6),
      Text(
        'Limit: blocks apply to traffic through PrivacyWatch. Traffic that bypasses the proxy is only stopped by a firewall '
        'rule, and a third-party firewall such as Norton may ignore Windows Firewall rules.',
        style: t.bodySmall,
      ),
    ]);
  }
}

class _Note extends StatelessWidget {
  const _Note(this.icon, this.color, this.text);
  final IconData icon;
  final Color color;
  final String text;

  @override
  Widget build(BuildContext context) => Container(
        width: double.infinity,
        margin: const EdgeInsets.only(bottom: 8),
        padding: const EdgeInsets.all(8),
        decoration: BoxDecoration(
          color: color.withValues(alpha: 0.12),
          border: Border.all(color: color),
          borderRadius: BorderRadius.circular(6),
        ),
        child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Icon(icon, color: color, size: 18),
          const SizedBox(width: 8),
          Expanded(child: Text(text)),
        ]),
      );
}

/// Shows the impact of each blocking choice for one app or one destination, with the buttons to act on it.
class BlockDecisionPanel extends StatefulWidget {
  const BlockDecisionPanel.app({super.key, required this.blocker, required AppImpact this.app}) : dest = null;
  const BlockDecisionPanel.destination({super.key, required this.blocker, required DestImpact this.dest}) : app = null;

  final AppBlocker? blocker;
  final AppImpact? app;
  final DestImpact? dest;

  @override
  State<BlockDecisionPanel> createState() => _BlockDecisionPanelState();
}

class _BlockDecisionPanelState extends State<BlockDecisionPanel> {
  bool _busy = false;
  String? _result;

  AppBlocker? get b => widget.blocker;

  Future<void> _blockApp(AppImpact a) async {
    setState(() => _busy = true);
    final fw = await b!.block(a.name, a.path);
    if (!mounted) return;
    setState(() {
      _busy = false;
      _result = fw
          ? '${a.name} is blocked (proxy and Windows Firewall rule).'
          : '${a.name} is blocked for traffic through the proxy. No firewall rule was created (permission declined or path unknown).';
    });
  }

  @override
  Widget build(BuildContext context) {
    final a = widget.app, d = widget.dest;
    final rec = a?.recommendation ?? d!.recommendation;
    final lines = a?.impactLines ?? d!.impactLines;
    final prefersApp = a?.preferApp ?? false;
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      _Note(Icons.lightbulb, prefersApp ? Colors.red.shade700 : Colors.blue, rec),
      for (final l in lines) Padding(padding: const EdgeInsets.only(bottom: 4), child: Text('- $l')),
      if (_busy) const _Note(Icons.admin_panel_settings, Colors.blue, 'Waiting for Windows permission - approve the prompt.'),
      if (_result != null) _Note(Icons.check_circle, Colors.green.shade800, _result!),
      if (b != null) ...[
        const SizedBox(height: 4),
        Wrap(spacing: 8, runSpacing: 8, children: [
          if (a != null) ..._appButtons(a),
          if (d != null) _destButton(d),
        ]),
      ],
      const SizedBox(height: 4),
      const ExpansionTile(
        tilePadding: EdgeInsets.zero,
        title: Text('App or destination - how do they differ?'),
        children: [BlockingGuide()],
      ),
      const Divider(),
    ]);
  }

  List<Widget> _appButtons(AppImpact a) {
    final blocked = b!.isBlocked(a.name, a.path);
    final allBlocked = a.concernHosts.isNotEmpty && a.concernHosts.every(b!.isHostBlocked);
    final destBtn = a.concernHosts.isEmpty
        ? null
        : _btn(
            primary: !a.preferApp,
            onPressed: allBlocked ? null : () => setState(() => a.concernHosts.forEach(b!.blockHost)),
            icon: Icons.public_off,
            label: allBlocked ? 'Destinations blocked' : 'Block ${a.concernHosts.length} concerning destination(s)',
          );
    final appBtn = _btn(
      primary: a.preferApp,
      onPressed: (_busy || blocked) ? null : () => _blockApp(a),
      icon: Icons.block,
      label: blocked ? 'App blocked' : 'Block this app',
    );
    return [?destBtn, appBtn];
  }

  Widget _btn({required bool primary, required VoidCallback? onPressed, required IconData icon, required String label}) =>
      primary
          ? FilledButton.icon(onPressed: onPressed, icon: Icon(icon), label: Text(label))
          : OutlinedButton.icon(onPressed: onPressed, icon: Icon(icon), label: Text(label));

  Widget _destButton(DestImpact d) {
    final blocked = b!.isHostBlocked(d.host);
    return FilledButton.icon(
      onPressed: () => setState(() => blocked ? b!.unblockHost(d.host) : b!.blockHost(d.host)),
      icon: Icon(blocked ? Icons.lock_open : Icons.public_off),
      label: Text(blocked ? 'Blocked - tap to unblock' : 'Block this destination'),
    );
  }
}
