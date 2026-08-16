<?php
declare(strict_types=1);

namespace BadBehaviour\Util;

/**
 * Immutable result of a LogRetention::do_cleanup() call.
 *
 * Fields:
 *   - success:           true iff at least one DELETE was issued AND no errors
 *   - rows_deleted:      total rows deleted across all DELETE iterations
 *   - iterations:        number of DELETE statements issued (1+ for chunked
 *                        deletes on large tables; 0 if nothing matched)
 *   - elapsed_seconds:   wall-clock time spent in do_cleanup()
 *   - cutoff_computed:   the timestamp used as the age cutoff (unix seconds)
 *   - log_table:         the table the DELETE was issued against
 *   - limit_by:          'age' (deleted by date < cutoff) or 'rows'
 *                        (deleted by max_rows cap) or 'none' (nothing to delete)
 *   - error:             exception message on total failure (null on success)
 */
final readonly class RetentionResult
{
    public function __construct(
        public bool $success,
        public int $rows_deleted,
        public int $iterations,
        public float $elapsed_seconds,
        public int $cutoff_computed,
        public string $log_table,
        public string $limit_by,
        public ?string $error = null,
    ) {}

    public function to_array(): array
    {
        return [
            'success'         => $this->success,
            'rows_deleted'    => $this->rows_deleted,
            'iterations'      => $this->iterations,
            'elapsed_seconds' => round($this->elapsed_seconds, 4),
            'cutoff_computed' => $this->cutoff_computed,
            'log_table'       => $this->log_table,
            'limit_by'        => $this->limit_by,
            'error'           => $this->error,
        ];
    }
}