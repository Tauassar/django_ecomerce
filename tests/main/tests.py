"""
This file demonstrates writing tests using the unittest module. These will pass
when you run "manage.py test".

Replace this with more appropriate tests for your application.
"""
import mock

from django.shortcuts import render
from django.test import TestCase
from django.urls import resolve
from django.test import RequestFactory

from main.views import index


class MainPageTests(TestCase):
    """
    SETUP
    """

    def setUp(self):
        request_factory = RequestFactory()
        self.request = request_factory.get('/')
        self.request.session = {}

    """
    TEST ROUTES
    """

    def test_root_resolves_to_main_view(self):
        main_page = resolve('/')
        self.assertEqual(main_page.func, index)
        self.assertEqual(main_page.url_name, 'home')

    def test_returns_appropriate_html(self):
        index_page = self.client.get('/')
        self.assertEqual(index_page.status_code, 200)

    """
    TEST TEMPLATES AND VIEWS
    """

    def test_uses_index_html_template(self):
        index_page = self.client.get('/')
        self.assertTemplateUsed(index_page, 'index.html')

    def test_uses_exact_html(self):
        index_page = self.client.get('/')

        self.assertEquals(
            index_page.content.decode(),
            render(request=None, template_name='index.html').content.decode()
        )

    def test_handles_logged_in_user(self):

        # SET SESSION
        self.request.session = {'user': '1'}

        with mock.patch('main.views.User') as user_mock:
            config = {'get_by_id.return_value': mock.Mock()}
            user_mock.objects.configure_mock(**config)

            response = index(self.request)

            expected_html = render(request=None,
                                   template_name='user.html',
                                   context={'user': user_mock.get_by_id(1)}
                                   )

            # VERIFY RESPONSE SAME FOR BOTH CASES
            self.assertEquals(response.content,
                              expected_html.content
                              )
