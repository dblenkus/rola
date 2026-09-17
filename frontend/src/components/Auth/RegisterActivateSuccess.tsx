import React from 'react';

import { useTranslation } from 'react-i18next';

import Success from './utils/Success';

interface RegisterActivateSuccessProps {
    onClick: () => void;
}

const RegisterActivateSuccess: React.FC<RegisterActivateSuccessProps> = (props) => {
    const { onClick } = props;
    const { t } = useTranslation();

    return (
        <Success title={t('activation_succeeded')} buttonText={t('goto_login')} onClick={onClick} />
    );
};

export default RegisterActivateSuccess;
