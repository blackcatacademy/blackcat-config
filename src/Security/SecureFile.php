<?php

declare(strict_types=1);

namespace BlackCat\Config\Security;

final class SecureFile
{
    public static function assertSecureReadableFile(string $path, ?ConfigFilePolicy $policy = null): void
    {
        $policy ??= ConfigFilePolicy::strict();

        $path = trim($path);
        if ($path === '') {
            throw new SecurityException('Config file path is empty.');
        }
        if (str_contains($path, "\0")) {
            throw new SecurityException('Config file path contains null byte.');
        }

        if (!file_exists($path)) {
            throw new SecurityException('Config file not found: ' . $path);
        }
        if (!$policy->allowSymlinks && is_link($path)) {
            throw new SecurityException('Config file must not be a symlink: ' . $path);
        }
        if (!is_file($path)) {
            throw new SecurityException('Config path is not a file: ' . $path);
        }
        if (!is_readable($path)) {
            throw new SecurityException('Config file is not readable: ' . $path);
        }

        $size = filesize($path);
        if (!is_int($size)) {
            throw new SecurityException('Unable to read config file size: ' . $path);
        }
        if ($size > $policy->maxBytes) {
            throw new SecurityException(sprintf(
                'Config file too large (%d B > %d B): %s',
                $size,
                $policy->maxBytes,
                $path
            ));
        }

        self::assertSecurePermissions($path, $policy);
    }

    private static function assertSecurePermissions(string $path, ConfigFilePolicy $policy): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            return;
        }

        $perms = fileperms($path);
        if (!is_int($perms)) {
            throw new SecurityException('Unable to read config file permissions: ' . $path);
        }
        $mode = $perms & 0777;

        if (!$policy->allowWorldWritable && (($mode & 0o002) !== 0)) {
            throw new SecurityException(sprintf('Config file must not be world-writable (%o): %s', $mode, $path));
        }
        if (!$policy->allowGroupWritable && (($mode & 0o020) !== 0)) {
            throw new SecurityException(sprintf('Config file must not be group-writable (%o): %s', $mode, $path));
        }
        if (!$policy->allowWorldReadable && (($mode & 0o004) !== 0)) {
            throw new SecurityException(sprintf('Config file must not be world-readable (%o): %s', $mode, $path));
        }

        $dir = dirname($path);
        if ($dir === '' || $dir === '.' || $dir === DIRECTORY_SEPARATOR) {
            return;
        }

        if ($policy->checkParentDirs) {
            self::assertParentDirsNotWritable($dir);
            return;
        }

        self::assertDirNotWritable($dir);
    }

    private static function assertParentDirsNotWritable(string $startDir): void
    {
        $dir = $startDir;
        while ($dir !== '' && $dir !== '.' && $dir !== DIRECTORY_SEPARATOR) {
            self::assertDirNotWritable($dir);
            $parent = dirname($dir);
            if ($parent === $dir) {
                break;
            }
            $dir = $parent;
        }
    }

    private static function assertDirNotWritable(string $dir): void
    {
        $perms = fileperms($dir);
        if (!is_int($perms)) {
            throw new SecurityException('Unable to read directory permissions: ' . $dir);
        }

        $mode = $perms & 0777;
        $sticky = ($perms & 0o1000) !== 0;
        if (($mode & 0o002) !== 0 && !$sticky) {
            throw new SecurityException(sprintf('Config directory must not be world-writable (%o): %s', $mode, $dir));
        }
        if (($mode & 0o020) !== 0 && !$sticky) {
            throw new SecurityException(sprintf('Config directory must not be group-writable (%o): %s', $mode, $dir));
        }
    }
}
