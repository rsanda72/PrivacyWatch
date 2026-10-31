import 'package:flutter/material.dart';

import 'core/app_blocker.dart';
import 'core/event.dart';
import 'core/pii_detector.dart';
import 'report_page.dart';

/// Pop-up shown when a Critical transaction is detected.
class CriticalAlertDialog extends StatefulWidget {
  const CriticalAlertDialog({super.key, required this.event, required this.blocker, required this.onViewReport});
  final TransactionEvent event;
  final AppBlocker blocker;
  final VoidCallback onViewReport;

  @override
  State<CriticalAlertDialog> createState() => _CriticalAlertDialogState();
}

class _CriticalAlertDialogState extends State<CriticalAlertDialog> {
  bool _busy = false;
  String? _result;
  String? _warning;

  TransactionEvent get e => widget.event;
  String get _appName => e.appName ?? 'unknown app';
  String get _host => e.host;
  bool get _blocked => widget.blocker.isBlocked(e.appName, e.appPath);
  bool get _hostBlocked => widget.blocker.isHostBlocked(_host);

  Future<void> _block() async {
    setState(() => _busy = true);
    final fw = await widget.blocker.block(_appName, e.appPath);
    final other = fw ? await widget.blocker.thirdPartyFirewall() : null;
    if (!mounted) return;
    setState(() {
      _busy = false;
      _result = fw
          ? '$_appName is blocked in PrivacyWatch (all traffic through the proxy) and a Windows Firewall rule was created.'
          : '$_appName is blocked in PrivacyWatch (traffic through the proxy only). No firewall rule was created '
              '(permission declined or path unknown).';
      _warning = other == null
          ? null
          : '$other is installed and may be the active firewall. It can ignore the Windows Firewall rule, so '
              'traffic that bypasses the proxy may NOT be blocked. Add the same block in $other to be sure.';
    });
  }

  void _blockHost() {
    widget.blocker.blockHost(_host);
    setState(() {
      _result = '$_host (and its subdomains) is blocked for every application using the proxy. '
          '$_appName can still reach other sites.';
      _warning = null;
    });
  }

  @override
  Widget build(BuildContext context) {
    final steps = [
      'Verify: check the data type and where it appeared; a 13-19 digit number can be a false positive.',
      'Check the program: is it expected? Look at its location and digital signature.',
      if (e.appPath == null) 'The program path could not be determined; find it in Task Manager > Details.',
      'If the data is real, contact your card issuer / change affected passwords.',
      'Run a full Microsoft Defender scan; uninstall the program if you do not trust it.',
      'Keep the log (%USERPROFILE%\\PrivacyWatch\\transactions.jsonl) as evidence.',
    ];
    return AlertDialog(
      icon: Icon(Icons.gpp_maybe, color: severityColor(Severity.critical), size: 40),
      title: Row(children: [
        const Expanded(child: Text('Critical: personal data detected')),
        SeverityChip(e.severity),
      ]),
      content: SizedBox(
        width: 560,
        child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
          if (_busy)
            const _Banner(Icons.admin_panel_settings, Colors.blue,
                'Waiting for Windows permission - approve the prompt (it may be behind this window).'),
          if (!_busy && (_result != null || _blocked || _hostBlocked))
            _Banner(Icons.check_circle, Colors.green.shade800,
                _result ?? (_blocked ? '$_appName is already blocked.' : '$_host is already blocked.')),
          if (!_busy && _warning != null) _Banner(Icons.warning_amber, Colors.deepOrange, _warning!),
          Flexible(
            child: SingleChildScrollView(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisSize: MainAxisSize.min, children: [
            _row('Who', e.app ?? 'unknown app'),
            if (e.appPath != null) _row('Program', e.appPath!),
            _row('Sent to', e.destination),
            _row('How', '${e.how}${e.encrypted ? '' : '  (UNENCRYPTED - readable by anyone on the network path)'}'),
            _row('Size', 'up ${TransactionEvent.formatBytes(e.bytesUp)}, down ${TransactionEvent.formatBytes(e.bytesDown)}'),
            _row('When', e.time.toIso8601String()),
            const Divider(),
            const Text('What was found', style: TextStyle(fontWeight: FontWeight.bold)),
            for (final m in e.what)
              Padding(
                padding: const EdgeInsets.only(top: 4),
                child: Text('- ${m.category.label} in ${m.where} (${m.redacted}): ${m.category.explanation}'),
              ),
            const Divider(),
            const Text('Recommended steps', style: TextStyle(fontWeight: FontWeight.bold)),
            for (var i = 0; i < steps.length; i++) Padding(padding: const EdgeInsets.only(top: 4), child: Text('${i + 1}. ${steps[i]}')),
            const Divider(),
            const Text('Blocking options', style: TextStyle(fontWeight: FontWeight.bold)),
            const Padding(
              padding: EdgeInsets.only(top: 4),
              child: Text('- Block this destination: stops every application using the proxy from reaching this site. '
                  'The app keeps working elsewhere. Best when the app is shared or legitimate (browser, curl, PowerShell).'),
            ),
            const Padding(
              padding: EdgeInsets.only(top: 4),
              child: Text('- Block this app: stops ALL traffic from this program, legitimate or not, until you unblock it. '
                  'Best for an unknown or untrusted program.'),
            ),
            const Padding(
              padding: EdgeInsets.only(top: 4),
              child: Text('- Limit: blocks apply to traffic through PrivacyWatch. Traffic that bypasses the proxy is only '
                  'stopped by a firewall rule, and a third-party firewall such as Norton may ignore Windows Firewall rules.'),
            ),
              ]),
            ),
          ),
        ]),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.of(context).pop(), child: const Text('Dismiss')),
        TextButton(
          onPressed: () {
            Navigator.of(context).pop();
            widget.onViewReport();
          },
          child: const Text('View report'),
        ),
        OutlinedButton.icon(
          onPressed: (_busy || _hostBlocked) ? null : _blockHost,
          icon: const Icon(Icons.public_off),
          label: Text(_hostBlocked ? 'Destination blocked' : 'Block this destination'),
        ),
        FilledButton.icon(
          style: FilledButton.styleFrom(backgroundColor: severityColor(Severity.critical)),
          onPressed: (_busy || _blocked) ? null : _block,
          icon: _busy
              ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
              : const Icon(Icons.block),
          label: Text(_blocked ? 'App blocked' : 'Block this app (Windows asks permission)'),
        ),
      ],
    );
  }

  Widget _row(String k, String v) => Padding(
        padding: const EdgeInsets.only(bottom: 4),
        child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
          SizedBox(width: 70, child: Text(k, style: const TextStyle(fontWeight: FontWeight.bold))),
          Expanded(child: SelectableText(v)),
        ]),
      );
}

class _Banner extends StatelessWidget {
  const _Banner(this.icon, this.color, this.text);
  final IconData icon;
  final Color color;
  final String text;

  @override
  Widget build(BuildContext context) => Container(
        width: double.infinity,
        margin: const EdgeInsets.only(bottom: 12),
        padding: const EdgeInsets.all(10),
        decoration: BoxDecoration(
          color: color.withValues(alpha: 0.12),
          border: Border.all(color: color),
          borderRadius: BorderRadius.circular(6),
        ),
        child: Row(children: [
          Icon(icon, color: color),
          const SizedBox(width: 8),
          Expanded(child: Text(text, style: TextStyle(color: color, fontWeight: FontWeight.bold))),
        ]),
      );
}

/// Lists blocked apps and lets the user unblock them.
class BlockedAppsDialog extends StatefulWidget {
  const BlockedAppsDialog({super.key, required this.blocker});
  final AppBlocker blocker;

  @override
  State<BlockedAppsDialog> createState() => _BlockedAppsDialogState();
}

class _BlockedAppsDialogState extends State<BlockedAppsDialog> {
  String? _note;

  @override
  Widget build(BuildContext context) {
    final entries = widget.blocker.apps.entries.toList();
    return AlertDialog(
      title: const Text('Blocked applications and destinations'),
      content: SizedBox(
        width: 480,
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          if (_note != null) _Banner(Icons.info, Colors.deepOrange, _note!),
          if (entries.isEmpty && widget.blocker.hosts.isEmpty)
            const Text('Nothing is blocked.')
          else
            Flexible(
              child: SingleChildScrollView(
                child: Column(mainAxisSize: MainAxisSize.min, children: [
                  for (final h in widget.blocker.hosts.toList())
                    ListTile(
                      leading: const Icon(Icons.public_off, color: Colors.red),
                      title: Text(h),
                      subtitle: const Text('Destination blocked for all applications (proxy)'),
                      trailing: TextButton(
                        onPressed: () => setState(() => widget.blocker.unblockHost(h)),
                        child: const Text('Unblock'),
                      ),
                    ),
                  for (final en in entries)
                    ListTile(
                      leading: const Icon(Icons.block, color: Colors.red),
                      title: Text(en.value.name),
                      subtitle: Text('${en.value.path ?? 'path unknown'}\n'
                          '${en.value.firewallRule ? 'Proxy + firewall rule' : 'Proxy only'}'),
                      isThreeLine: true,
                      trailing: TextButton(
                        onPressed: () async {
                          final clean = await widget.blocker.unblock(en.key);
                          if (!mounted) return;
                          setState(() => _note = clean
                              ? null
                              : '${en.value.name} is unblocked in PrivacyWatch, but its Windows Firewall rule is still there '
                                  '(permission declined). It will reappear here next start.');
                        },
                        child: const Text('Unblock'),
                      ),
                    ),
                ]),
              ),
            ),
        ]),
      ),
      actions: [TextButton(onPressed: () => Navigator.of(context).pop(), child: const Text('Close'))],
    );
  }
}
