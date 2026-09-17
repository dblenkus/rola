import React from 'react';

import { useTranslation } from 'react-i18next';

import Confirm from './utils/Confirm';

interface RegisterConfirmProps {
    email: string;
}

const RegisterConfirm: React.FC<RegisterConfirmProps> = (props) => {
    const { email } = props;
    const { t } = useTranslation();

    return (
        <Confirm title={t('registration_confirmed_title')}>
            {t('registration_confirmed', { email })}
        </Confirm>
    );
};

export default RegisterConfirm;
