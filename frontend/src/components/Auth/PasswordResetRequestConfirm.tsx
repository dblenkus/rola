import React from 'react';

import { useTranslation } from 'react-i18next';

import Confirm from './utils/Confirm';

interface PasswordResetRequestConfirmProps {
    email: string;
}

const PasswordResetRequestConfirm: React.FC<PasswordResetRequestConfirmProps> = (props) => {
    const { email } = props;
    const { t } = useTranslation();

    return (
        <Confirm title={t('reset_link_sent_title', { email })}>
            {t('reset_link_sent', { email })}
        </Confirm>
    );
};

export default PasswordResetRequestConfirm;
