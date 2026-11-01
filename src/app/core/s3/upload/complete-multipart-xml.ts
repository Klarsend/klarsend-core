/**
 * CompleteMultipartUpload request-body writer (slice 21). The commit call's XML
 * names every uploaded part IN PART-NUMBER ORDER with the ETag receipt S3
 * handed back for it; only at THIS moment does the object come into existence —
 * un-completed parts are invisible to listings and recipients (though, unlike
 * Azure's blocks, they BILL until aborted — the provider's abandon story).
 *
 * The serialisation matches `@aws-sdk/client-s3`'s byte-for-byte — member order
 * `<ETag>` before `<PartNumber>`, the model's namespace on the root — pinned by
 * the SDK-equality spec against a body captured from the real SDK offline.
 * ETags are sent exactly as received (S3 returns them quoted; we round-trip the
 * quotes). Escaping is defensive: real part ETags contain no XML-significant
 * characters, but the writer is safe on its own terms, not by a property of its
 * current caller.
 */

export interface CompletedPart {
  /** 1-based S3 part number. */
  partNumber: number;
  /** The `ETag` response header from UploadPart, verbatim (quotes included). */
  etag: string;
}

/**
 * All five XML entities, exactly as the AWS SDK's writer escapes text — ETags
 * are quoted, so `"` → `&quot;` is load-bearing for byte-equality.
 */
function escapeXml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

/** The exact request body for CompleteMultipartUpload over `parts`. */
export function completeMultipartXml(parts: readonly CompletedPart[]): string {
  const entries = [...parts]
    .sort((a, b) => a.partNumber - b.partNumber)
    .map(
      (p) =>
        `<Part><ETag>${escapeXml(p.etag)}</ETag><PartNumber>${p.partNumber}</PartNumber></Part>`,
    )
    .join('');
  return (
    '<?xml version="1.0" encoding="UTF-8"?>' +
    `<CompleteMultipartUpload xmlns="http://s3.amazonaws.com/doc/2006-03-01/">${entries}</CompleteMultipartUpload>`
  );
}
