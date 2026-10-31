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
  final apps = <String, BlockedApp>{};
  final hosts = <String>{}; // blocked destinations (and their subdomains), for every app

  static String keyOf(String? name, String? path) => (path ?? name ?? '').toLowerCase();

  bool get isEmpty => apps.isEmpty && hosts.isEmpty;
  bool isBlocked(String? name, String? path) => apps.containsKey(keyOf(name, path));

  void blockHost(String host) => hosts.add(host.toLowerCase());
  void unblockHost(String host) => hosts.remove(host.toLowerCase());
  bool isHostBlocked(String host) {
    final h = host.toLowerCase();
    return hosts.any((b) => h == b || h.endsWith('.$b'));
  }

  /// Returns true if the firewall rule was created as well.
  Future<bool> block(String name, String? path) async {
    final app = BlockedApp(name, path);
    apps[keyOf(name, path)] = app;
    if (!Platform.isWindows || path == null) return false;
    await _runElevated(
        "New-NetFirewallRule -DisplayName '${_q(app.ruleName)}' -Direction Outbound -Program '${_q(path)}' -Action Block");
    app.firewallRule = await _ruleExists(app.ruleName);
    return app.firewallRule;
  }

  Future<void> unblock(String key) async {
    final app = apps.remove(key);
    if (app != null && app.firewallRule) {
      await _runElevated("Remove-NetFirewallRule -DisplayName '${_q(app.ruleName)}' -ErrorAction SilentlyContinue");
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
