using System.Runtime.InteropServices;

// Системные библиотеки объявлений LibraryImport этой сборки (iphlpapi, cfgmgr32, eappcfg, wtsapi32, netapi32, crypt32,
// kernel32, ntdll, shell32) ищутся только в System32, как и у обёрток CsWin32. Без этого среда .NET сначала искала бы их
// в каталоге сборки: подложенная туда DLL загрузилась бы в службу LocalSystem. Каталог установки закрыт на запись
// (installer\Package.wxs), так что это вторая линия защиты. Исключение - wintun.dll (SystemSshTunnelOps): она поставляется
// рядом с программой, и её объявления сами задают поиск в каталоге программы.
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
