<?php

declare(strict_types=1);

namespace BlackCat\Config\Runtime;

use BlackCat\Config\Security\ConfigDirPolicy;
use BlackCat\Config\Security\ConfigFilePolicy;
use BlackCat\Config\Security\SecureDir;
use BlackCat\Config\Security\SecureFile;
use BlackCat\Config\Security\SecurityException;

/**
 * @phpstan-type RuntimeFinding array{
 *   severity:'info'|'warn'|'error',
 *   code:string,
 *   message:string,
 *   meta?:array<string,mixed>
 * }
 */
final class RuntimeDoctor
{
    /**
     * @return array{
     *   ok:bool,
     *   tier:'strong'|'medium'|'compat',
     *   source_path:?string,
     *   findings:list<array{
     *     severity:'info'|'warn'|'error',
     *     code:string,
     *     message:string,
     *     meta?:array<string,mixed>
     *   }>,
     *   summary:array{errors:int,warnings:int,infos:int}
     * }
     */
    public static function inspect(ConfigRepository $repo): array
    {
        /** @var list<RuntimeFinding> $findings */
        $findings = [];

        /** @var callable('info'|'warn'|'error', string, string, array<string,mixed>|null):void $add */
        /**
         * @param 'info'|'warn'|'error' $severity
         * @param array<string,mixed>|null $meta
         */
        $add = static function (string $severity, string $code, string $message, ?array $meta = null) use (&$findings): void {
            /** @var RuntimeFinding $row */
            $row = [
                'severity' => $severity,
                'code' => $code,
                'message' => $message,
            ];
            if ($meta !== null && $meta !== []) {
                /** @var array<string,mixed> $normalizedMeta */
                $normalizedMeta = [];
                foreach ($meta as $k => $v) {
                    if (is_string($k) && $k !== '' && !ctype_digit($k)) {
                        $normalizedMeta[$k] = $v;
                    }
                }
                if ($normalizedMeta !== []) {
                    $row['meta'] = $normalizedMeta;
                }
            }
            $findings[] = $row;
        };

        $sourcePath = $repo->sourcePath();
        if ($sourcePath === null) {
            $add('warn', 'runtime_config_source_unknown', 'Runtime config has no known source path (in-memory repo).', null);
        } else {
            try {
                SecureFile::assertSecureReadableFile($sourcePath, ConfigFilePolicy::strict());
                $add('info', 'runtime_config_file_ok', 'Runtime config file passes strict file policy.', [
                    'path' => $sourcePath,
                ]);
            } catch (SecurityException $e) {
                $add('error', 'runtime_config_file_insecure', 'Runtime config file is not secure under strict policy.', [
                    'path' => $sourcePath,
                    'reason' => $e->getMessage(),
                ]);
            }

            if (str_starts_with(str_replace('\\', '/', $sourcePath), '/mnt/')) {
                $add(
                    'warn',
                    'runtime_config_on_windows_mount',
                    'Runtime config is stored on a Windows mount (/mnt/*). Prefer WSL filesystem or a Linux volume for security-critical config.',
                    ['path' => $sourcePath],
                );
            }
        }

        self::runValidatorChecks($repo, $add);
        self::checkRecommendedTrustKernelPosture($repo, $add);
        self::checkRecommendedSecretsBoundary($repo, $add);
        self::checkTxOutboxDir($repo, $add);
        self::checkPhpIniPosture($add);

        $summary = [
            'errors' => 0,
            'warnings' => 0,
            'infos' => 0,
        ];
        foreach ($findings as $finding) {
            $sev = $finding['severity'];
            if ($sev === 'error') {
                $summary['errors']++;
            } elseif ($sev === 'warn') {
                $summary['warnings']++;
            } else {
                $summary['infos']++;
            }
        }

        $tier = self::deriveTier($repo, $findings);

        return [
            'ok' => $summary['errors'] === 0,
            'tier' => $tier,
            'source_path' => $sourcePath,
            'findings' => $findings,
            'summary' => $summary,
        ];
    }

    /**
     * @param callable('info'|'warn'|'error', string, string, array<string,mixed>|null):void $add
     */
    private static function runValidatorChecks(ConfigRepository $repo, callable $add): void
    {
        $checks = [
            'http' => static function () use ($repo): void {
                RuntimeConfigValidator::assertHttpConfig($repo);
            },
            'crypto' => static function () use ($repo): void {
                RuntimeConfigValidator::assertCryptoConfig($repo);
            },
            'db' => static function () use ($repo): void {
                RuntimeConfigValidator::assertDbConfig($repo);
            },
            'observability' => static function () use ($repo): void {
                RuntimeConfigValidator::assertObservabilityConfig($repo);
            },
            'trust.web3' => static function () use ($repo): void {
                RuntimeConfigValidator::assertTrustKernelWeb3Config($repo);
            },
        ];

        foreach ($checks as $name => $fn) {
            try {
                $fn();
                $add('info', 'config_valid_' . $name, 'Runtime config section validated: ' . $name, null);
            } catch (\Throwable $e) {
                // Treat missing optional sections as info, not errors.
                $raw = $repo->get($name);
                if ($raw === null && in_array($name, ['http', 'crypto', 'db', 'observability', 'trust.web3'], true)) {
                    $add('info', 'config_missing_' . $name, 'Runtime config section not present: ' . $name, null);
                    continue;
                }
                $add('error', 'config_invalid_' . $name, 'Runtime config validation failed for: ' . $name, [
                    'error' => $e->getMessage(),
                ]);
            }
        }
    }

    /**
     * @param callable('info'|'warn'|'error', string, string, array<string,mixed>|null):void $add
     */
    private static function checkRecommendedTrustKernelPosture(ConfigRepository $repo, callable $add): void
    {
        $web3 = $repo->get('trust.web3');
        if ($web3 === null) {
            $add(
                'warn',
                'trust_kernel_not_configured',
                'TrustKernel (trust.web3) is not configured; integrity checks and fail-closed enforcement are disabled.',
                null,
            );
            return;
        }

        $endpoints = $repo->get('trust.web3.rpc_endpoints');
        $count = is_array($endpoints) ? count($endpoints) : 0;

        $quorum = null;
        $qRaw = $repo->get('trust.web3.rpc_quorum');
        if (is_int($qRaw)) {
            $quorum = $qRaw;
        } elseif (is_string($qRaw) && ctype_digit(trim($qRaw))) {
            $quorum = (int) trim($qRaw);
        }

        if ($count > 0 && $quorum !== null && ($count < 2 || $quorum < 2)) {
            $add(
                'warn',
                'rpc_quorum_insecure_for_strict',
                'Strict TrustKernel policy requires at least 2 independent RPC endpoints and quorum >= 2. With quorum=1 a single RPC can lie about on-chain state.',
                [
                    'rpc_endpoints_count' => $count,
                    'rpc_quorum' => $quorum,
                ]
            );
        }
    }

    /**
     * @param callable('info'|'warn'|'error', string, string, array<string,mixed>|null):void $add
     */
    private static function checkRecommendedSecretsBoundary(ConfigRepository $repo, callable $add): void
    {
        if ($repo->get('trust.web3') === null) {
            return;
        }

        $cryptoAgent = $repo->get('crypto.agent.socket_path');
        if (!is_string($cryptoAgent) || trim($cryptoAgent) === '') {
            $add(
                'warn',
                'crypto_agent_missing',
                'crypto.agent.socket_path is not configured. Key material may need to be readable by the web runtime (higher exfil risk on RCE). Prefer secrets-agent mode.',
                null,
            );
        }

        $dbAgent = $repo->get('db.agent.socket_path');
        if ($repo->get('db') !== null && (!is_string($dbAgent) || trim($dbAgent) === '')) {
            $add(
                'warn',
                'db_agent_missing',
                'db.agent.socket_path is not configured. DB credentials may be exposed to the web runtime unless a secrets boundary is used.',
                null,
            );
        }
    }

    /**
     * @param callable('info'|'warn'|'error', string, string, array<string,mixed>|null):void $add
     */
    private static function checkTxOutboxDir(ConfigRepository $repo, callable $add): void
    {
        if ($repo->get('trust.web3') === null) {
            return;
        }

        $txOutbox = $repo->get('trust.web3.tx_outbox_dir');
        if ($txOutbox === null || $txOutbox === '') {
            $add(
                'warn',
                'tx_outbox_not_configured',
                'trust.web3.tx_outbox_dir is not configured. Recommended for buffering on-chain incident/check-in transactions via external relayers.',
                null,
            );
            return;
        }

        if (!is_string($txOutbox)) {
            return;
        }

        try {
            $resolved = $repo->resolvePath($txOutbox);
            SecureDir::assertSecureReadableDir($resolved, ConfigDirPolicy::txOutboxDir());
            if (!is_writable($resolved)) {
                $add('warn', 'tx_outbox_not_writable', 'Configured tx outbox directory is not writable by this process.', [
                    'path' => $resolved,
                ]);
            } else {
                $add('info', 'tx_outbox_ok', 'Tx outbox directory is configured and writable.', [
                    'path' => $resolved,
                ]);
            }
        } catch (\Throwable $e) {
            $add('warn', 'tx_outbox_invalid', 'Tx outbox directory is configured but does not satisfy security policy.', [
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * @param callable('info'|'warn'|'error', string, string, array<string,mixed>|null):void $add
     */
    private static function checkPhpIniPosture(callable $add): void
    {
        $get = static function (string $key): ?string {
            $v = ini_get($key);
            return is_string($v) ? $v : null;
        };

        $flag = static function (?string $v): ?bool {
            if ($v === null) {
                return null;
            }
            $t = strtolower(trim($v));
            if ($t === '') {
                return null;
            }
            if (in_array($t, ['1', 'on', 'yes', 'true'], true)) {
                return true;
            }
            if (in_array($t, ['0', 'off', 'no', 'false'], true)) {
                return false;
            }
            if (ctype_digit($t)) {
                return ((int) $t) !== 0;
            }
            return null;
        };

        $openBasedir = $get('open_basedir');
        if ($openBasedir === null || trim($openBasedir) === '') {
            $add(
                'warn',
                'php_open_basedir_unset',
                'open_basedir is not set. Strict TrustKernel policy will fail-closed; set open_basedir to include your code root + /etc/blackcat + /var/lib/blackcat.',
                null,
            );
        }

        $allowUrlInclude = $flag($get('allow_url_include'));
        if ($allowUrlInclude === true) {
            $add('warn', 'php_allow_url_include_enabled', 'allow_url_include is enabled (high-risk RFI). Set allow_url_include=0.', null);
        }

        $pharReadonly = $flag($get('phar.readonly'));
        if ($pharReadonly === false) {
            $add('warn', 'php_phar_readonly_disabled', 'phar.readonly is disabled. Set phar.readonly=1 to reduce PHAR deserialization risks.', null);
        }

        $disableFunctions = $get('disable_functions');
        if ($disableFunctions === null || trim($disableFunctions) === '') {
            $add(
                'warn',
                'php_disable_functions_empty',
                'disable_functions is empty. Consider disabling process execution primitives (exec,shell_exec,system,passthru,popen,proc_open,pcntl_exec) for web runtimes.',
                null,
            );
        }
    }

    /**
     * @param list<array{severity:'info'|'warn'|'error',code:string,message:string,meta?:array<string,mixed>}> $findings
     * @return 'strong'|'medium'|'compat'
     */
    private static function deriveTier(ConfigRepository $repo, array $findings): string
    {
        $hasWeb3 = $repo->get('trust.web3') !== null;
        if (!$hasWeb3) {
            return 'compat';
        }

        $hasErrors = false;
        $hasWarnings = false;
        foreach ($findings as $f) {
            if ($f['severity'] === 'error') {
                $hasErrors = true;
            } elseif ($f['severity'] === 'warn') {
                $hasWarnings = true;
            }
        }

        if ($hasErrors) {
            return 'compat';
        }
        if ($hasWarnings) {
            return 'medium';
        }
        return 'strong';
    }
}
