import { useTranslation } from 'react-i18next';

import Button from '../../../shared/ui/Button';
import './UploadButton.css';

interface UploadButtonProps {
  contestId: number;
  // The details page shows the action twice; only one may be primary.
  variant: 'primary' | 'secondary';
}

// The link to a contest's upload page, drawn as a large button.
export default function UploadButton({
  contestId,
  variant,
}: UploadButtonProps) {
  const { t } = useTranslation();
  return (
    <div className="contests-upload">
      <Button
        variant={variant}
        size="large"
        to={`/contest/${contestId}/upload`}
      >
        {t('upload_photos')}
      </Button>
    </div>
  );
}
