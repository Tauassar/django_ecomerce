"""
This file demonstrates writing tests using the unittest module. These will pass
when you run "manage.py test".

Replace this with more appropriate tests for your application.
"""
import re
from unittest import TestCase

import mock
from django.db import IntegrityError
from django.shortcuts import render
from django.urls import resolve

from django_ecommerce import settings
from payments.models import User
from django.test import RequestFactory
from payments.forms import SigninForm, UserForm
from payments.views import sign_in, soon, register

"""
    TODO: 
    1. Add test in ViewTesterMixin for checking if appropriate template used inside a view 
"""


class UserModelTest(TestCase):

    def setUp(self):
        self.test_user = User(
            email='test@test.com',
            name='test user'
        )
        self.test_user.save()

    def tearDown(self):
        self.test_user.delete()

    def test_user_get_string(self):
        """
        Tests User model's __str__ function.
        """
        self.assertEquals(str(self.test_user), self.test_user.email)

    def test_get_user_by_id(self):
        """
        Tests User model's get_by_id function.
        """
        test_user = User.objects.get(email=self.test_user.email)
        self.assertEquals(User.get_by_id(test_user.id), self.test_user)


class FormTesterMixin:

    def assertFormError(self, form_cls, expected_error_name,
                        expected_error_msg, data):
        from pprint import pformat
        test_form = form_cls(data=data)

        # If error, form should not be valid
        self.assertFalse(test_form.is_valid())

        self.assertEquals(
            test_form.errors[expected_error_name],
            expected_error_msg,
            msg=f'Expected {expected_error_msg}, '
                f'Actual {test_form.errors[expected_error_name]} '
                f'using data {pformat(data)}'
        )


class FormTests(TestCase, FormTesterMixin):

    def test_sign_in_form_validation_for_invalid_data(self):
        invalid_data_list = [
            {'data': {'email': 'j@j.com'},
             'error': ('password', [u'This field is required.'])},
            {'data': {'password': '1234'},
             'error': ('email', [u'This field is required.'])},
        ]
        for invalid_data in invalid_data_list:
            self.assertFormError(SigninForm, invalid_data['error'][0],
                                 invalid_data['error'][1],
                                 invalid_data['data'])

    def test_user_form_password_match(self):
        form = UserForm(
            {
                'name': 'jj',
                'email': 'jj@jj.com',
                'password': '1234',
                'ver_password': '1234',
                'last_4_digits': '3333',
                'stripe_token': '1'
            }
        )
        # Check if data is valid, if not, print out an errors
        self.assertTrue(form.is_valid(), form.errors)

        # Throw an error if data does not clean correctly
        self.assertIsNotNone(form.clean())

    # def test_user_form_password_does_not_match_throws_error(self):
    #     form = UserForm(
    #         {
    #             'name': 'jj',
    #             'email': 'jj@jj.com',
    #             'password': '1234',
    #             'ver_password': '12345',
    #             'last_4_digit': '3333',
    #             'stripe_token': '1'
    #         }
    #     )
    #     # Check if data is valid, if not, print out an errors
    #     self.assertFalse(form.is_valid())
    #     # self.assertR
    #     self.assertRaises(form.clean, None, None,
    #                       django.forms.ValidationError,
    #                       'Passwords do not match',
    #                       )


class ViewTesterMixin(object):
    @classmethod
    def setupViewTester(cls, url, view_func, expected_html, status_code=200, session={}):
        request_factory = RequestFactory()
        cls.request = request_factory.get(url)
        cls.request.session = session
        cls.status_code = status_code
        cls.url = url
        cls.view_func = staticmethod(view_func)
        cls.template_name = expected_html['name']
        cls.expected_html = render(
            request=cls.request,
            template_name=expected_html['name'],
            context=expected_html['context']
        ).content.decode()

    def test_resolves_to_correct_view(self):
        test_view = resolve(self.url)
        self.assertEqual(test_view.func, self.view_func)

    def test_returns_appropriate_response_code(self):
        response = self.view_func(self.request)
        self.assertEquals(response.status_code, self.status_code)

    def delete_csrf_from_html(self, inp):
        try:
            csrf_regex = r'<input[^>]+csrfmiddlewaretoken[^>]+>'
            return re.sub(csrf_regex, '', inp)
        except TypeError:
            print(inp)
            print('Passed object is not a string')
            return self.delete_csrf_from_html(str(inp))

    def test_returns_correct_html(self):
        response = self.view_func(self.request)
        self.assertEquals(
            self.delete_csrf_from_html(response.content.decode()),
            self.delete_csrf_from_html(self.expected_html),
            f'\nFailed test {self.template_name}'
        )


class SignInPageTests(TestCase, ViewTesterMixin):

    @classmethod
    def setUpClass(cls) -> None:
        html = {
            'name': 'sign_in.html',
            'context': {
                'form': SigninForm(),
                'user': None
            }
        }
        ViewTesterMixin.setupViewTester(
            url='/sign_in',
            view_func=sign_in,
            expected_html=html
        )


class RegisterPageTests(TestCase, ViewTesterMixin):

    @classmethod
    def setUpClass(cls) -> None:
        html = {
            'name': 'register.html',
            'context': {
                'form': UserForm(),
                'months': range(1, 12),
                'publishable': settings.STRIPE_PUBLISHABLE,
                'soon': soon(),
                'user': None,
                'years': range(2011, 2036),
            }
        }
        ViewTesterMixin.setupViewTester(
            '/register',
            register,
            html
        )

    def setUp(self) -> None:
        request_factory = RequestFactory()
        self.request = request_factory.get(self.url)

    def test_invalid_form_returns_registration_page(self):
        with mock.patch('payments.forms.UserForm.is_valid') as user_mock:
            user_mock.return_value = False
            self.request.method = 'POST'
            self.request.POST = None
            response = register(self.request)
            self.assertEquals(
                self.delete_csrf_from_html(response.content.decode()),
                self.delete_csrf_from_html(self.expected_html)
            )
            # make sure that call to mock indeed happened
            self.assertEquals(user_mock.call_count, 1)

    @mock.patch('stripe.Customer.create')
    @mock.patch.object(User, 'create')
    def test_registering_new_user_returns_successfully(self, create_mock, stripe_mock):
        self.request.session = {}
        self.request.method = 'POST'
        self.request.POST = {
            'email': 'python@rocks.com',
            'name': 'pyRock',
            'stripe_token': '...',
            'last_4_digits': '4242',
            'password': 'bad_password',
            'ver_password': 'bad_password',
        }

        new_user = create_mock.return_value
        new_cust = stripe_mock.return_value

        response = register(self.request)

        self.assertEquals(response.content.decode(), '')
        self.assertEquals(response.status_code, 302)
        self.assertEquals(self.request.session['user'], new_user.pk)
        # verify the user was actually stored in the database.
        create_mock.assert_called_with(
            'pyRock', 'python@rocks.com', 'bad_password', '4242',
            new_cust.id
        )


    def test_registering_user_twice_cause_error_message(self):
        # create a new user
        try:
            user = User(
                name='pyRock',
                email='python@rocks.com'
            )
            user.save()
        except IntegrityError:
            print('\nTest user for test_registering_user_twice_throws_error already created')

        self.request.session = {}
        self.request.method = 'POST'
        self.request.POST = {
            'email': 'python@rocks.com',
            'name': 'pyRock',
            'stripe_token': '...',
            'last_4_digits': '4242',
            'password': 'bad_password',
            'ver_password': 'bad_password',
        }

        # create an expected form
        expected_form = UserForm(self.request.POST)
        expected_form.is_valid()
        expected_form.addError('python@rocks.com is already a member')
        html = render(
            request=self.request,
            template_name=self.template_name,
            context={
                'form': expected_form,
                'months': range(1, 12),
                'publishable': settings.STRIPE_PUBLISHABLE,
                'soon': soon(),
                'user': None,
                'years': range(2011,2036)
            }
        )

        # mock Stripe value
        with mock.patch('stripe.Customer') as mock_stripe:
            config = {
                'create.return_value': mock.Mock(),
                'create.return_value.id': 1
            }
            mock_stripe.configure_mock(**config)

            # tests
            response = register(self.request)
            # verify everything is OK
            self.assertEquals(response.status_code, 200)
            self.assertEquals(self.request.session, {})
            # check if second object was added to database
            self.assertEquals(len(User.objects.filter(email=self.request.POST['email'])), 1)
            self.assertEquals(
                self.delete_csrf_from_html(response.content.decode()),
                self.delete_csrf_from_html(html.content.decode())
            )

    def test_create_user_function_stores_in_database(self):
        user = User.create(
            'test',
            'test@t.com',
            'tt',
            '1234',
            '22'
        )
        self.assertEquals(User.objects.get(email=user.email), user)

    def test_create_user_already_exists_throws_IntegrityError(self):
        # Create new user
        User.create(
            'test user',
            'j@j.com',
            'jj',
            '1234',
            89
        )
        # check if create function throws IntegrityError
        self.assertRaises(
            IntegrityError,
            User.create,
            'test user',
            'j@j.com',
            'jj',
            '1234',
            89
        )

