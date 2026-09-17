import React from 'react';

import Success from './utils/Success';

interface PasswordResetSuccessProps {
    onClick: () => void;
}

const PasswordResetSuccess: React.FC<PasswordResetSuccessProps> = (props) => {
    const { onClick } = props;

    return (
        <Success
            title="Password was successfully reset!"
            buttonText="Go to Log in"
            onClick={onClick}
        />
    );
};

export default PasswordResetSuccess;
