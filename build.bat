CALL "C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\vcvarsall.bat" amd64
set CYGWIN=nodosfilewarning
set WIRESHARK_BASE_DIR=C:\work
set WIRESHARK_TARGET_PLATFORM=win64
set QT5_BASE_DIR=C:\Qt\Qt5.3.2\5.3\msvc2013_opengl
set WIRESHARK_VERSION_EXTRA=2
cd "C:\work\wireshark\plugins"
nmake /f Custom.nmake all
xcopy "C:\work\wireshark\plugins\xdp\xdp.dll" "C:\Program Files\Wireshark\plugins\1.12.6" /Y
"C:\Program Files\Wireshark\Wireshark.exe"