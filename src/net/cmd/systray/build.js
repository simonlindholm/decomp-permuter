const { execSync } = require('child_process')

switch (process.platform) {
  case 'darwin':
    execSync('go build -o ./tray_darwin tray.go')
    execSync('go build -o ./tray_darwin_release -ldflags "-s -w" tray.go')
    break;
  case 'linux':
    execSync('go build -o ./tray_linux tray.go')
    execSync('go build -o ./tray_linux_release -ldflags "-s -w" tray.go')
    break;
  case 'win32':
    execSync('go build -o ./tray_windows.exe tray.go')
    execSync('go build -o ./tray_windows_release.exe -ldflags "-s -w" tray.go')
    break;
  default:
}
