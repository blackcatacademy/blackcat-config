<?php

declare(strict_types=1);

namespace BlackCat\Config\Runtime;

use BlackCat\Config\Security\ConfigFilePolicy;
use BlackCat\Config\Security\SecureFile;

/**
 * Best-available runtime config installer.
 *
 * Goal:
 * - pick the safest writable location available on the current system
 * - create the runtime config file with strict permissions when possible
 * - remain usable on platforms where POSIX permissions are not available (Windows)
 */
final class RuntimeConfigInstaller
{
    /**
     * @return list<string>
     */
    public static function defaultWritePaths(): array
    {
        return DIRECTORY_SEPARATOR === '\\'
            ? self::defaultWritePathsWindows()
            : self::defaultWritePathsPosix();
    }

    /**
     * Recommend the best writable path (without writing).
     *
     * @param list<string>|null $candidates
     * @return array{path:?string,reason:string,rejected:array<string,string>,candidates:list<string>}
     */
    public static function recommendWritePath(?array $candidates = null): array
    {
        $candidates = $candidates !== null ? array_values($candidates) : self::defaultWritePaths();

        $normalized = [];
        foreach ($candidates as $path) {
            $path = trim((string) $path);
            if ($path === '') {
                continue;
            }
            $normalized[] = $path;
        }
        $normalized = array_values(array_unique($normalized));

        $rejected = [];

        foreach ($normalized as $path) {
            if (is_file($path)) {
                try {
                    SecureFile::assertSecureReadableFile($path, ConfigFilePolicy::strict());
                    return [
                        'path' => $path,
                        'reason' => 'Existing runtime config file is present and passes strict validation.',
                        'rejected' => $rejected,
                        'candidates' => $normalized,
                    ];
                } catch (\Throwable $e) {
                    $rejected[$path] = $e->getMessage();
                    continue;
                }
            }

            $parent = self::nearestExistingDir(dirname($path));
            if ($parent === null) {
                $rejected[$path] = 'No existing parent directory found.';
                continue;
            }
            if (!is_writable($parent)) {
                $rejected[$path] = 'Parent directory is not writable: ' . $parent;
                continue;
            }

            return [
                'path' => $path,
                'reason' => 'Parent directory is writable: ' . $parent,
                'rejected' => $rejected,
                'candidates' => $normalized,
            ];
        }

        return [
            'path' => null,
            'reason' => 'No writable candidate path found.',
            'rejected' => $rejected,
            'candidates' => $normalized,
        ];
    }

    /**
     * Create (or reuse) runtime config file in the best available location.
     *
     * - If `$path` is provided, only that path is used.
     * - Otherwise, candidates are tried in priority order.
     *
     * @param array<string,mixed> $payload JSON payload written into the config file (default: {}).
     * @param list<string>|null $candidates
     * @return array{path:string,created:bool,rejected:array<string,string>}
     */
    public static function init(array $payload = [], ?string $path = null, bool $force = false, ?array $candidates = null): array
    {
        $list = [];
        if ($path !== null) {
            $path = trim($path);
            if ($path !== '') {
                $list = [$path];
            }
        }
        if ($list === []) {
            $list = $candidates !== null ? array_values($candidates) : self::defaultWritePaths();
        }

        $rejected = [];

        foreach ($list as $candidate) {
            $candidate = trim((string) $candidate);
            if ($candidate === '') {
                continue;
            }

            try {
                $created = self::ensureRuntimeConfigFile($candidate, $payload, $force);
                // Validate post-write to ensure this location is actually usable by strict readers.
                SecureFile::assertSecureReadableFile($candidate, ConfigFilePolicy::strict());

                return [
                    'path' => $candidate,
                    'created' => $created,
                    'rejected' => $rejected,
                ];
            } catch (\Throwable $e) {
                $rejected[$candidate] = $e->getMessage();
                continue;
            }
        }

        $lines = [];
        foreach ($rejected as $p => $reason) {
            $lines[] = sprintf('- %s: %s', $p, $reason);
        }

        throw new \RuntimeException(sprintf(
            "Unable to initialize runtime config file.\nRejected candidates:\n%s",
            $lines !== [] ? implode("\n", $lines) : '(none)',
        ));
    }

    /**
     * @param array<string,mixed> $payload
     */
    private static function ensureRuntimeConfigFile(string $path, array $payload, bool $force): bool
    {
        $path = trim($path);
        if ($path === '') {
            throw new \InvalidArgumentException('Runtime config path is empty.');
        }
        if (str_contains($path, "\0")) {
            throw new \InvalidArgumentException('Runtime config path contains null byte.');
        }

        $dir = dirname($path);
        if ($dir === '' || $dir === '.' || $dir === DIRECTORY_SEPARATOR) {
            throw new \RuntimeException('Runtime config path must not be root: ' . $path);
        }

        self::assertNoSymlinkParents($dir);

        if (!is_dir($dir)) {
            if (!@mkdir($dir, 0750, true) && !is_dir($dir)) {
                throw new \RuntimeException('Unable to create config directory: ' . $dir);
            }
            if (DIRECTORY_SEPARATOR !== '\\') {
                @chmod($dir, 0750);
            }
        }

        if (is_link($dir)) {
            throw new \RuntimeException('Config directory must not be a symlink: ' . $dir);
        }

        if (is_file($path)) {
            if (is_link($path)) {
                throw new \RuntimeException('Runtime config file must not be a symlink: ' . $path);
            }

            // If the existing file is valid and we are not forcing a rewrite, keep it.
            try {
                SecureFile::assertSecureReadableFile($path, ConfigFilePolicy::strict());
                return false;
            } catch (\Throwable $e) {
                if (!$force) {
                    throw new \RuntimeException(
                        'Existing runtime config file is not secure/valid: ' . $e->getMessage() . ' (use --force to overwrite)'
                    );
                }
            }
        } elseif (file_exists($path)) {
            throw new \RuntimeException('Runtime config path exists but is not a file: ' . $path);
        }

        $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if (!is_string($json)) {
            throw new \RuntimeException('Unable to encode runtime config JSON.');
        }

        $tmp = $dir . DIRECTORY_SEPARATOR . '.blackcat-config.' . bin2hex(random_bytes(8)) . '.tmp';
        $fp = @fopen($tmp, 'xb');
        if ($fp === false) {
            throw new \RuntimeException('Unable to create temp file in: ' . $dir);
        }

        try {
            $bytes = fwrite($fp, $json . "\n");
            if ($bytes === false) {
                throw new \RuntimeException('Unable to write runtime config temp file.');
            }
        } finally {
            fclose($fp);
        }

        if (DIRECTORY_SEPARATOR !== '\\') {
            @chmod($tmp, 0600);
        }

        if (!@rename($tmp, $path)) {
            @unlink($tmp);
            throw new \RuntimeException('Unable to move runtime config into place: ' . $path);
        }

        if (DIRECTORY_SEPARATOR !== '\\') {
            @chmod($path, 0600);
        }

        return true;
    }

    private static function nearestExistingDir(string $dir): ?string
    {
        $dir = trim($dir);
        if ($dir === '' || $dir === '.') {
            return null;
        }

        while ($dir !== '' && $dir !== '.' && $dir !== DIRECTORY_SEPARATOR) {
            if (is_dir($dir)) {
                return $dir;
            }
            $parent = dirname($dir);
            if ($parent === $dir) {
                break;
            }
            $dir = $parent;
        }

        return is_dir(DIRECTORY_SEPARATOR) ? DIRECTORY_SEPARATOR : null;
    }

    private static function assertNoSymlinkParents(string $dir): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            return;
        }

        $dir = rtrim($dir, '/');
        if ($dir === '') {
            return;
        }

        $prefix = str_starts_with($dir, '/') ? '/' : '';
        $parts = array_values(array_filter(explode('/', ltrim($dir, '/')), static fn (string $p): bool => $p !== ''));

        $cur = $prefix;
        foreach ($parts as $part) {
            $cur = $cur === '/' ? $cur . $part : $cur . '/' . $part;
            if (is_link($cur)) {
                throw new \RuntimeException('Parent directory must not be a symlink: ' . $cur);
            }
        }
    }

    /**
     * @return list<string>
     */
    private static function defaultWritePathsPosix(): array
    {
        $paths = [
            '/etc/blackcat/config.runtime.json',
            '/etc/blackcat/config.json',
        ];

        $home = self::homeDir();
        if ($home !== null) {
            $paths[] = $home . '/.config/blackcat/config.runtime.json';
            $paths[] = $home . '/.blackcat/config.runtime.json';
        }

        // Last-resort: local working directory (only if the runtime is constrained).
        $cwd = @getcwd();
        if (is_string($cwd) && $cwd !== '') {
            $paths[] = rtrim($cwd, '/\\') . '/.blackcat/config.runtime.json';
        }

        return $paths;
    }

    /**
     * @return list<string>
     */
    private static function defaultWritePathsWindows(): array
    {
        $paths = [
            'C:\\ProgramData\\BlackCat\\config.runtime.json',
        ];

        $appData = self::serverString('APPDATA');
        if ($appData !== null) {
            $paths[] = rtrim($appData, '\\/') . '\\BlackCat\\config.runtime.json';
        }

        $localAppData = self::serverString('LOCALAPPDATA');
        if ($localAppData !== null) {
            $paths[] = rtrim($localAppData, '\\/') . '\\BlackCat\\config.runtime.json';
        }

        $profile = self::serverString('USERPROFILE');
        if ($profile !== null) {
            $paths[] = rtrim($profile, '\\/') . '\\.blackcat\\config.runtime.json';
        }

        return $paths;
    }

    private static function homeDir(): ?string
    {
        $home = self::serverString('HOME');
        if ($home !== null) {
            return rtrim($home, "\\/");
        }

        if (DIRECTORY_SEPARATOR !== '\\' && function_exists('posix_getpwuid') && function_exists('posix_geteuid')) {
            /** @var array{dir?:mixed}|false $info */
            $info = posix_getpwuid(posix_geteuid());
            $dir = is_array($info) ? ($info['dir'] ?? null) : null;
            if (is_string($dir) && $dir !== '') {
                return rtrim($dir, "\\/");
            }
        }

        $profile = self::serverString('USERPROFILE');
        if ($profile !== null) {
            return rtrim($profile, "\\/");
        }

        return null;
    }

    private static function serverString(string $key): ?string
    {
        $val = $_SERVER[$key] ?? null;
        if (!is_string($val)) {
            return null;
        }
        $val = trim($val);
        return $val !== '' ? $val : null;
    }
}
