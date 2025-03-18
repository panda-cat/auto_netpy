# -*- mode: python -*-
from PyInstaller.utils.hooks import collect_all

block_cipher = None

# 包含所有依赖
datas, binaries, hiddenimports = collect_all('nornir')

a = Analysis(
    ['src/nornir_netops.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='nornir_netops',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,  # 启用UPX压缩
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # 显示控制台窗口
    icon='icon.ico', # 可选图标
    disable_windowed_tracker=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
