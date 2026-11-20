import type { JurySubmission } from '../../../shared/api/types';
import './Photographs.css';

interface PhotographsProps {
  files: JurySubmission['files'];
  // The submission's title as shown; it is each photograph's alt text.
  title: string;
  onError: () => void;
  onLoad: () => void;
}

// The photograph on screen whole, or every photograph of a series whole with
// its place in the series. Nothing is cropped, zoomed, rounded or laid over
// them, and they change without a transition.
export default function Photographs({
  files,
  title,
  onError,
  onLoad,
}: PhotographsProps) {
  if (files.length === 1) {
    const [file] = files;
    return (
      <div className="judge-photos">
        {file && (
          <img
            className="judge-photos__single"
            src={file.file}
            alt={title}
            onError={onError}
            onLoad={onLoad}
          />
        )}
      </div>
    );
  }
  return (
    <div className="judge-photos">
      <div className="judge-photos__series">
        {files.map((file, index) => (
          <figure key={file.id} className="judge-photos__figure">
            <img
              className="judge-photos__photo"
              src={file.file}
              alt={title}
              onError={onError}
              onLoad={onLoad}
            />
            <figcaption className="judge-photos__caption mono-caption">
              {index + 1} / {files.length}
            </figcaption>
          </figure>
        ))}
      </div>
    </div>
  );
}
