import React from 'react';
import { Dialog, Heading, Modal, ModalOverlay } from 'react-aria-components';
import { useTranslation } from 'react-i18next';
import Button, { ButtonRow } from './Button';
import './ConfirmDialog.css';

interface ConfirmDialogProps {
  children: React.ReactNode;
  // Names the dialog.
  title: string;
  open: boolean;
  // Called when the dialog closes: "No", Escape, a press outside it, and
  // before onConfirm on "Yes".
  onClose: () => void;
  onConfirm: () => void;
}

// Asks to confirm an action in a modal dialog. Focus moves into it and
// returns to where it was when it closes.
const ConfirmDialog: React.FC<ConfirmDialogProps> = (props) => {
  const { title, children, open, onClose, onConfirm } = props;

  const { t } = useTranslation();

  const handleConfirm = () => {
    onClose();
    onConfirm();
  };

  return (
    <ModalOverlay
      className="ui-dialog-overlay"
      isOpen={open}
      onOpenChange={(isOpen) => {
        if (!isOpen) onClose();
      }}
      isDismissable
    >
      <Modal className="ui-dialog">
        <Dialog className="ui-dialog__panel">
          <Heading slot="title" className="ui-dialog__title h4">
            {title}
          </Heading>
          <div className="ui-dialog__content body">{children}</div>
          <ButtonRow>
            <Button onPress={onClose}>{t('no')}</Button>
            <Button variant="primary" onPress={handleConfirm}>
              {t('yes')}
            </Button>
          </ButtonRow>
        </Dialog>
      </Modal>
    </ModalOverlay>
  );
};
export default ConfirmDialog;
