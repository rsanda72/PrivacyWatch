import 'dart:convert';
import 'dart:io';

/// Findings the user has reviewed, so they stop showing as new alerts. Kept in acks.json across restarts.
class AckStore {
  AckStore._();
  static final AckStore instance = AckStore._();

  File? _file;
  final _keys = <String>{};

  static String key(String category, String? app, String host) => '$category|${app ?? ''}|$host';

  void attach(File file) {
    if (_file?.path == file.path) return;
    _file = file;
    _keys.clear();
    try {
      if (file.existsSync()) _keys.addAll((jsonDecode(file.readAsStringSync()) as List).cast<String>());
    } catch (_) {}
  }

  bool has(String k) => _keys.contains(k);

  void add(Iterable<String> keys) {
    _keys.addAll(keys);
    _save();
  }

  void remove(String k) {
    _keys.remove(k);
    _save();
  }

  void _save() {
    try {
      _file?.writeAsStringSync(jsonEncode(_keys.toList()));
    } catch (_) {}
  }
}
