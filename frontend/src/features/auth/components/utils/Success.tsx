import Button from '../../../../shared/ui/Button';
import '../AuthPage.css';

interface SuccessProps {
  title: string;
  buttonText: string;
  // Goes to the next step; the pages replace their own history entry.
  onClick: () => void;
}

// A screen that says an account action succeeded, with the one next step.
export default function Success({ buttonText, title, onClick }: SuccessProps) {
  return (
    <div className="auth-status">
      <h2 className="auth-status__title h3">{title}</h2>
      <div className="auth-status__action">
        <Button variant="primary" block onPress={onClick}>
          {buttonText}
        </Button>
      </div>
    </div>
  );
}
