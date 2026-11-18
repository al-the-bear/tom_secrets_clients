// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The layout of the manager app's distribution, which carries `tsm` and
/// the service with it, so the app needs nothing else installed: the
/// command-line tools as `dart build cli` makes them (`bin/` with `tsm` and
/// `tom_secrets_service`, `lib/` with their native libraries) in a folder
/// `tsm`:
///
/// | Platform | App executable | Tools |
/// | --- | --- | --- |
/// | macOS | `Tom Secrets Manager.app/Contents/MacOS/tom_secrets_app` | `….app/Contents/Resources/tsm/bin/` |
/// | Windows | `<folder>\tom_secrets_app.exe` | `<folder>\tsm\bin\` |
/// | Linux | `<folder>/tom_secrets_app` | `<folder>/tsm/bin/` |
///
/// The app finds the service there ([tomSecretsServiceCandidates]); the
/// service admits the app there as an admin ([tomSecretsDistributionApp]).
library;

/// The folder of the distribution holding the command-line tools.
const String tomSecretsToolsFolder = 'tsm';

/// The manager app's executable name, without `.exe`.
const String tomSecretsAppExecutable = 'tom_secrets_app';

/// The service's executable name, without `.exe`.
const String tomSecretsServiceExecutable = 'tom_secrets_service';

String _join(List<String> parts, String separator) => parts.join(separator);

/// Where the app whose executable is in [appDirectory] looks for the
/// service, in order: beside itself (a development build, or a fleet
/// install), then in its distribution's tools folder ([operatingSystem] as
/// `Platform.operatingSystem` names it).
List<String> tomSecretsServiceCandidates(
  String appDirectory, {
  required String operatingSystem,
}) {
  final windows = operatingSystem == 'windows';
  final sep = windows ? r'\' : '/';
  final exe = '$tomSecretsServiceExecutable${windows ? '.exe' : ''}';
  return [
    _join([appDirectory, exe], sep),
    if (operatingSystem == 'macos')
      _join([
        appDirectory,
        '..',
        'Resources',
        tomSecretsToolsFolder,
        'bin',
        exe,
      ], sep)
    else
      _join([appDirectory, tomSecretsToolsFolder, 'bin', exe], sep),
  ];
}

/// The app of the distribution around a service whose executable is in
/// [serviceDirectory] (`…/tsm/bin`): the path its executable has when the
/// service is the distribution's, which the service admits as an admin
/// besides `tsm` and the app beside itself.
String tomSecretsDistributionApp(
  String serviceDirectory, {
  required String operatingSystem,
}) {
  final windows = operatingSystem == 'windows';
  final sep = windows ? r'\' : '/';
  final exe = '$tomSecretsAppExecutable${windows ? '.exe' : ''}';
  return operatingSystem == 'macos'
      ? _join([serviceDirectory, '..', '..', '..', 'MacOS', exe], sep)
      : _join([serviceDirectory, '..', '..', exe], sep);
}

/// The browser host `tsm-browser-host` beside the service whose executable
/// is [serviceExecutable] (where the service recognises it, protocol.md 5.5,
/// and where the distribution carries it).
String tomSecretsBrowserHostBeside(
  String serviceExecutable, {
  required String operatingSystem,
}) {
  final windows = operatingSystem == 'windows';
  final sep = windows ? r'\' : '/';
  final cut = serviceExecutable.lastIndexOf(sep);
  final dir = cut < 0 ? '.' : serviceExecutable.substring(0, cut);
  return '$dir$sep$_browserHostName${windows ? '.exe' : ''}';
}

/// The browser host's executable name, without `.exe` (the service names
/// it `tomSecretsBrowserHostName`; not exported here, since the service
/// exports this library beside its own).
const String _browserHostName = 'tsm-browser-host';
