import photoId from './photoId';

interface PhotoLabelProps {
  submissionId: number;
  // The photograph's place in the judge's order, from 1.
  position: number;
  total: number;
  // The title as shown, "Untitled" when the entrant gave none.
  title: string;
  description: string | null;
}

// The wall label of the photograph on screen: its anonymous ID and position,
// its title as the page's heading, and its description. Never the author.
export default function PhotoLabel({
  submissionId,
  position,
  total,
  title,
  description,
}: PhotoLabelProps) {
  return (
    <div className="rl-photo-label">
      <div className="rl-photo-label__meta photo-id">
        <span className="rl-photo-label__id">{photoId(submissionId)}</span>
        <span className="rl-photo-label__position">
          {position} / {total}
        </span>
      </div>
      <h1 className="rl-photo-label__title photo-title">{title}</h1>
      {description && (
        <p className="rl-photo-label__description body">{description}</p>
      )}
      <hr className="rl-photo-label__rule" />
    </div>
  );
}
