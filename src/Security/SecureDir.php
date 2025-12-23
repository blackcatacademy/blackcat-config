<?php

declare(strict_types=1);

namespace BlackCat\Config\Security;

final class SecureDir
{
    public static function assertSecureReadableDir(string $path, ?ConfigDirPolicy $policy = null): void
    {
        $policy ??= ConfigDirPolicy::secretsDir();

        $path = trim($path);
        if ($path === '') {
            throw new SecurityException('Config directory path is empty.');
        }
        if (str_contains($path, "\0")) {
            throw new SecurityException('Config directory path contains null byte.');
        }

        if (!file_exists($path)) {
            throw new SecurityException('Config directory not found: ' . $path);
        }
        if (!$policy->allowSymlinks && is_link($path)) {
            throw new SecurityException('Config directory must not be a symlink: ' . $path);
        }
        if (!is_dir($path)) {
            throw new SecurityException('Config path is not a directory: ' . $path);
        }
        if (!is_readable($path)) {
            throw new SecurityException('Config directory is not readable: ' . $path);
        }

        self::assertSecurePermissions($path, $policy);
    }

    private static function assertSecurePermissions(string $path, ConfigDirPolicy $policy): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            return;
        }

        $perms = fileperms($path);
        if (!is_int($perms)) {
            throw new SecurityException('Unable to read directory permissions: ' . $path);
        }
        $mode = $perms & 0777;

        if ($policy->enforceOwner) {
            self::assertOwnedByRootOrCurrentUser($path, 'Config directory');
        }

        if (!$policy->allowWorldWritable && (($mode & 0o002) !== 0)) {
            throw new SecurityException(sprintf('Config directory must not be world-writable (%o): %s', $mode, $path));
        }
        if (!$policy->allowGroupWritable && (($mode & 0o020) !== 0)) {
            throw new SecurityException(sprintf('Config directory must not be group-writable (%o): %s', $mode, $path));
        }
        if (!$policy->allowWorldReadable && (($mode & 0o004) !== 0)) {
            throw new SecurityException(sprintf('Config directory must not be world-readable (%o): %s', $mode, $path));
        }
        if (!$policy->allowWorldExecutable && (($mode & 0o001) !== 0)) {
            throw new SecurityException(sprintf('Config directory must not be world-executable (%o): %s', $mode, $path));
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

    private static function assertOwnedByRootOrCurrentUser(string $path, string $label): void
    {
        if (!function_exists('posix_geteuid')) {
            return;
        }

        $owner = fileowner($path);
        if (!is_int($owner)) {
            throw new SecurityException('Unable to read owner for: ' . $path);
        }

        $euid = posix_geteuid();
        if (!is_int($euid)) {
            return;
        }

        if ($owner !== 0 && $owner !== $euid) {
            throw new SecurityException(sprintf(
                '%s must be owned by root or uid %d (got uid %d): %s',
                $label,
                $euid,
                $owner,
                $path
            ));
        }
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
