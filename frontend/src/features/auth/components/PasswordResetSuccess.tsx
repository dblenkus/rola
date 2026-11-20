import React from 'react';
import { useTranslation } from 'react-i18next';

import Success from './utils/Success';

interface PasswordResetSuccessProps {
  onClick: () => void;
}

const PasswordResetSuccess: React.FC<PasswordResetSuccessProps> = (props) => {
  const { onClick } = props;
  const { t } = useTranslation();

  return (
    <Success
      title={t('password_reset_succeeded')}
      buttonText={t('password_reset_goto_login')}
      onClick={onClick}
    />
  );
};

export default PasswordResetSuccess;
