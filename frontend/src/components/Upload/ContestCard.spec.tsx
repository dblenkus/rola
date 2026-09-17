import React from 'react';
import { Link } from 'react-router-dom';

import { shallow, ShallowWrapper } from 'enzyme';

import { contestMock } from '../../utils/tests/mocks';

import ContestCard from './ContestCard';

describe('ContestCard', () => {
    let wrapper: ShallowWrapper;
    beforeEach(() => {
        wrapper = shallow(<ContestCard contest={contestMock} />);
    });

    it('should contain title', () => {
        expect(wrapper.text()).toMatch(contestMock.title);
    });
    it('should contain description', () => {
        expect(wrapper.text()).toMatch(contestMock.description);
    });

    describe('Open button', () => {
        let links: ShallowWrapper<any>;
        beforeEach(() => {
            links = wrapper.find(Link);
        });
        it('should have an Open button', () => {
            expect(links).toHaveLength(1);
            expect(links.props().children).toEqual('Open');
        });
        it('should redirect to contest details', () => {
            expect(links.props().to).toEqual(`/contest/${contestMock.id}/details`);
        });
    });
});
