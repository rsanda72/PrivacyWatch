import 'dart:convert';
import 'dart:io';

class BlockedApp {
  BlockedApp(this.name, this.path, {this.firewallRule = false});
  final String name;
  final String? path;
  bool firewallRule; // true when an outbound Windows Firewall rule exists
  String get ruleName => 'PrivacyWatch block - $name';
}

/// Blocks an application two ways: immediately in the proxy (no admin needed),
/// and with a Windows Firewall rule (UAC prompt) that also covers traffic bypassing the proxy.
class AppBlocker {
  AppBlocker({this.storeFile});

  /// When set, blocks are saved here and restored on the next start.
  final File? storeFile;
  final apps = <String, BlockedApp>{};
  final hosts = <String>{}; // blocked destinations (and their subdomains), for every app

  static const _rulePrefix = 'PrivacyWatch block - ';

  static String keyOf(String? name, String? path) => (path ?? name ?? '').toLowerCase();

  bool get isEmpty => apps.isEmpty && hosts.isEmpty;
  bool isBlocked(String? name, String? path) => apps.containsKey(keyOf(name, path));

  void blockHost(String host) {
    hosts.add(host.toLowerCase());
    _save();
  }

  void unblockHost(String host) {
    hosts.remove(host.toLowerCase());
    _save();
  }

  bool isHostBlocked(String host) {
    final h = host.toLowerCase();
    return hosts.any((b) => h == b || h.endsWith('.$b'));
  }

  void _save() {
    try {
      storeFile?.writeAsStringSync(jsonEncode({
        'apps': [
          for (final a in apps.values) {'name': a.name, 'path': a.path, 'firewallRule': a.firewallRule}
        ],
        'hosts': hosts.toList(),
      }));
    } catch (_) {}
  }

  /// Restores saved blocks, then reconciles with the real Windows Firewall:
  /// rules that disappeared are dropped, and PrivacyWatch rules not in the
  /// saved list (for example from an earlier session) are adopted so they can be unblocked.
  Future<void> load({bool syncFirewall = true}) async {
    try {
      if (storeFile != null && storeFile!.existsSync()) {
        final j = jsonDecode(storeFile!.readAsStringSync()) as Map<String, dynamic>;
        for (final a in (j['apps'] as List? ?? const [])) {
          final app = BlockedApp(a['name'] as String, a['path'] as String?, firewallRule: a['firewallRule'] == true);
          apps[keyOf(app.name, app.path)] = app;
        }
        hosts.addAll(((j['hosts'] as List?) ?? const []).cast<String>());
      }
    } catch (_) {}
    if (syncFirewall && Platform.isWindows) {
      final rules = await _firewallRules();
      if (rules != null) {
        for (final a in apps.values) {
          a.firewallRule = rules.containsKey(a.ruleName);
        }
        rules.forEach((ruleName, program) {
          final name = ruleName.substring(_rulePrefix.length);
          final key = keyOf(name, program);
          apps.putIfAbsent(key, () => BlockedApp(name, program, firewallRule: true));
        });
      }
    }
    _save();
  }

  /// Returns true if the firewall rule was created as well.
  Future<bool> block(String name, String? path) async {
    final app = BlockedApp(name, path);
    apps[keyOf(name, path)] = app;
    if (!Platform.isWindows || path == null) {
      _save();
      return false;
    }
    // Reuse an existing rule instead of stacking duplicates.
    if (!await _ruleExists(app.ruleName)) {
      await _runElevated(
          "New-NetFirewallRule -DisplayName '${_q(app.ruleName)}' -Direction Outbound -Program '${_q(path)}' -Action Block");
    }
    app.firewallRule = await _ruleExists(app.ruleName);
    _save();
    return app.firewallRule;
  }

  /// Returns false if a firewall rule still exists afterwards (permission declined).
  Future<bool> unblock(String key) async {
    final app = apps.remove(key);
    _save();
    if (app == null || !app.firewallRule) return true;
    // Removing by name deletes every copy of the rule, including old duplicates.
    await _runElevated("Remove-NetFirewallRule -DisplayName '${_q(app.ruleName)}' -ErrorAction SilentlyContinue");
    return !await _ruleExists(app.ruleName);
  }

  /// Rule display name -> program path for every PrivacyWatch rule (null if the query fails).
  Future<Map<String, String?>?> _firewallRules() async {
    try {
      final r = await Process.run('powershell', [
        '-NoProfile',
        '-Command',
        "Get-NetFirewallRule -DisplayName '${_q(_rulePrefix)}*' -ErrorAction SilentlyContinue | "
            "ForEach-Object { \"\$(\$_.DisplayName)|\$((\$_ | Get-NetFirewallApplicationFilter).Program)\" }"
      ]);
      if (r.exitCode != 0) return null;
      final out = <String, String?>{};
      for (final line in (r.stdout as String).split('\n')) {
        final i = line.indexOf('|');
        if (i <= 0) continue;
        final p = line.substring(i + 1).trim();
        out[line.substring(0, i).trim()] = (p.isEmpty || p == 'Any') ? null : p;
      }
      return out;
    } catch (_) {
      return null;
    }
  }

  Future<String?> thirdPartyFirewall() async {
    if (!Platform.isWindows) return null;
    try {
      final r = await Process.run('powershell', [
        '-NoProfile',
        '-Command',
        "(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct -ErrorAction SilentlyContinue "
            "| Where-Object { \$_.displayName -notmatch 'Windows' } | Select-Object -First 1).displayName"
      ]);
      final n = (r.stdout as String).trim();
      return n.isEmpty ? null : n;
    } catch (_) {
      return null;
    }
  }

  static String _q(String s) => s.replaceAll("'", "''");

  Future<void> _runElevated(String script) async {
    final enc = base64.encode([for (final u in script.codeUnits) ...[u & 0xff, u >> 8]]);
    await Process.run('powershell', [
      '-NoProfile',
      '-Command',
      "try { Start-Process powershell -Verb RunAs -WindowStyle Hidden -Wait "
          "-ArgumentList '-NoProfile','-EncodedCommand','$enc' } catch {}"
    ]);
  }

  Future<bool> _ruleExists(String ruleName) async {
    final r = await Process.run('powershell', [
      '-NoProfile',
      '-Command',
      "@(Get-NetFirewallRule -DisplayName '${_q(ruleName)}' -ErrorAction SilentlyContinue).Count"
    ]);
    return (int.tryParse((r.stdout as String).trim()) ?? 0) > 0;
  }
}
