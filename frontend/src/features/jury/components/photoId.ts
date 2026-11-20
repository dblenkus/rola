// A submission's anonymous ID as the design system writes it: "#" and the id
// zero-padded to four digits ("#0275"). Longer ids keep all their digits.
export default function photoId(submissionId: number): string {
  if (!Number.isInteger(submissionId) || submissionId < 0) {
    throw new Error(`Invalid submission id: ${submissionId}`);
  }
  return `#${String(submissionId).padStart(4, '0')}`;
}
