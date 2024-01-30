import os
import time
import dateutil.parser
import re
import mimetypes

from dateutil.parser import parse
from pathlib import Path
from random import seed
from random import randint
from functools import wraps
from io import BytesIO
from logging.config import dictConfig

from flask import Flask, url_for, render_template, session, redirect, json, send_file
from flask_oauthlib.contrib.client import OAuth, OAuth2Application
from flask_session import Session
from xero_python.accounting import AccountingApi, Account, Accounts, AccountType, Allocation, Allocations, BatchPayment, BatchPayments, BankTransaction, BankTransactions, BankTransfer, BankTransfers, Contact, Contacts, ContactGroup, ContactGroups, ContactPerson, CreditNote, CreditNotes, Currency, Currencies, CurrencyCode, Employee, Employees, ExpenseClaim, ExpenseClaims, Invoice, Invoices, Item, Items, LineAmountTypes, LineItem, Payment, Payments, PaymentService, PaymentServices, Phone, Purchase, Receipt, Receipts, TaxType, User, Users
from xero_python.assets import AssetApi, Asset, AssetStatus, AssetStatusQueryParam, AssetType, BookDepreciationSetting
from xero_python.project import ProjectApi, Projects, ProjectCreateOrUpdate, ProjectPatch, ProjectStatus, ProjectUsers, TimeEntryCreateOrUpdate
from xero_python.payrollau import PayrollAuApi, Employees, Employee, EmployeeStatus,State, HomeAddress
from xero_python.payrolluk import PayrollUkApi, Employees, Employee, Address, Employment
from xero_python.payrollnz import PayrollNzApi, Employees, Employee, Address, Employment, EmployeeLeaveSetup
from xero_python.api_client import ApiClient, serialize
from xero_python.api_client.configuration import Configuration
from xero_python.api_client.oauth2 import OAuth2Token
from xero_python.exceptions import AccountingBadRequestException, PayrollUkBadRequestException
from xero_python.identity import IdentityApi
from xero_python.utils import getvalue

import logging_settings
from utils import jsonify, serialize_model

from flask import request, Response
import hashlib
import hmac
import base64



app = Flask(__name__)
app.config.from_object("default_settings")
app.config.from_pyfile("config.py", silent=True)

# configure persistent session cache
Session(app)


# configure flask-oauthlib application
# TODO fetch config from https://identity.xero.com/.well-known/openid-configuration #1
oauth = OAuth(app)
xero = oauth.remote_app(
    name="xero",
    version="2",
    client_id=app.config["CLIENT_ID"],
    client_secret=app.config["CLIENT_SECRET"],
    endpoint_url="https://api.xero.com/",
    authorization_url="https://login.xero.com/identity/connect/authorize",
    access_token_url="https://identity.xero.com/connect/token",
    refresh_token_url="https://identity.xero.com/connect/token",
    # scope="offline_access openid profile email accounting.transactions "
    # "accounting.transactions.read accounting.reports.read "
    # "accounting.journals.read accounting.settings accounting.settings.read "
    # "accounting.contacts accounting.contacts.read accounting.attachments "
    # "accounting.attachments.read assets projects "
    # "paymentservices "
    # "payroll.employees payroll.payruns payroll.payslip payroll.timesheets payroll.settings",
    scope = 'openid email profile offline_access accounting.transactions accounting.settings accounting.contacts',
)  # type: OAuth2Application

# configure xero-python sdk client
api_client = ApiClient(
    Configuration(
        debug=app.config["DEBUG"],
        oauth2_token=OAuth2Token(
            client_id=app.config["CLIENT_ID"], client_secret=app.config["CLIENT_SECRET"]
        ),
    ),
    pool_threads=1,
)

# configure token persistence and exchange point between flask-oauthlib and xero-python
@xero.tokengetter
@api_client.oauth2_token_getter
def obtain_xero_oauth2_token():
    return session.get("token")

@xero.tokensaver
@api_client.oauth2_token_saver
def store_xero_oauth2_token(token):
    session["token"] = token
    session.modified = True

def xero_token_required(function):
    @wraps(function)
    def decorator(*args, **kwargs):
        xero_token = obtain_xero_oauth2_token()
        if not xero_token:
            return redirect(url_for("login", _external=True))

        return function(*args, **kwargs)

    return decorator
  

@app.route("/")
def index():
    xero_access = dict(obtain_xero_oauth2_token() or {})
    return render_template(
        "base.html",
        title="Home | oauth token",
        code=json.dumps(xero_access, sort_keys=True, indent=4),
    )

@xero.tokengetter
def obtain_xero_oauth2_token():
    # Use the session to retrieve the access token
    return session.get("token")

def get_connection_id():
    identity_api = IdentityApi(api_client)
    for connection in identity_api.get_connections():
        if connection.tenant_type == "ORGANISATION":
            return connection.id
    
    
@app.route("/login")
def login():
    # redirect_url = url_for("oauth_callback", _external=True)
    # redirect_url = "https://gray-tree-05f7e4c00-develop.eastasia.3.azurestaticapps.net/"
    redirect_url ="http://localhost:5000/callback"
    response = xero.authorize(callback_uri=redirect_url)
    return response


@app.route("/callback")
def oauth_callback():
    try:
        response = xero.authorized_response()
    except Exception as e:
        print(e)
        raise
    # todo validate state value
    if response is None or response.get("access_token") is None:
        return "Access denied: response=%s" % response
    store_xero_oauth2_token(response)
    return redirect(url_for("index", _external=True))


@app.route("/disconnect")
def disconnect():
    connection_id = get_connection_id()
    identity_api = IdentityApi(api_client)
    identity_api.delete_connection(
        id=connection_id
    )

    return redirect(url_for("index", _external=True))

@app.route("/logout")
def logout():

    store_xero_oauth2_token(None)
    return redirect(url_for("index", _external=True))
  

@app.route("/export-token")
@xero_token_required
def export_token():
    token = obtain_xero_oauth2_token()
    buffer = BytesIO("token={!r}".format(token).encode("utf-8"))
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype="x.python",
        as_attachment=True,
        attachment_filename="oauth2_token.py",
    )


@app.route("/refresh-token")
@xero_token_required
def refresh_token():
    xero_token = obtain_xero_oauth2_token()
    new_token = api_client.refresh_oauth2_token()
    return render_template(
        "output.html",
        title="Xero OAuth2 token",
        code=jsonify({"Old Token": xero_token, "New token": new_token}),
        sub_title="token refreshed",
    )
    
# TODO AUTHORIZE with ORGANIZATIONS
@app.route("/authorize_xero", methods=["GET"])
@xero_token_required
def authorize_xero():
    # callback=url_for("oauth2callback", _external=True)
    callback = 'http://localhost:5000/callback'
    # callback =  'https://caad-1-87-243-242.ngrok-free.app/oauth2callback'     
    return xero.authorize(callback_uri=callback)

@app.route("/oauth2callback")
def oauth2callback():
    response = xero.authorized_response()
    if response and response.get("access_token"):
        # Store the new access token in the session
        session["token"] = {
            "access_token": response["access_token"],
            "token_type": response["token_type"],
            "expires_in": response["expires_in"],
        }
        session.modified = True

        # Redirect back to the tenants route to list the available organizations
        return redirect(url_for("tenants"))
    else:
        # Handle the case where the OAuth 2.0 authorization was not successful
        return "OAuth authorization failed."


# TODO TENANTS
@app.route("/tenants")
@xero_token_required
def tenants():
    identity_api = IdentityApi(api_client)
    accounting_api = AccountingApi(api_client)
    asset_api = AssetApi(api_client)

    available_tenants = []
    print("available_tenants:--------------------------------------------")
    for connection in identity_api.get_connections():
        tenant = serialize(connection)
        print(tenant)
        if connection.tenant_type == "ORGANISATION":
            organisations = accounting_api.get_organisations(
                xero_tenant_id=connection.tenant_id
            )
            tenant["organisations"] = serialize(organisations)
        available_tenants.append(tenant)
        
    # for web app only    
    session["tenants"] = available_tenants
    session["tenants_updated"] = True
    return redirect(request.referrer)

    # for azure function: 
    # return available_tenants



# TODO CONTACTs

@app.route("/accounting_contact_read_all", methods=["GET", "POST"])
@xero_token_required
def accounting_contact_read_all():
    if request.method == "POST":
        tenant_name = request.form.get("tenant_name")
        xero_tenant_id = None
        # Fetch the xero_tenant_id based on the provided tenant_name
        for tenant_data in session.get("tenants", []):
            if tenant_data["tenantName"] == tenant_name:
                xero_tenant_id = tenant_data["tenantId"]
                break

        if xero_tenant_id is None:
            print("Tenant not found.")
            return redirect(request.referrer)

        accounting_api = AccountingApi(api_client)

        try:
            read_contacts = accounting_api.get_contacts(
                xero_tenant_id
            )
        except AccountingBadRequestException as exception:
            output = "Error: " + exception.reason
            json = jsonify(exception.error_data)
        else:
            output = "Contact(s) read {} total".format(
                len(read_contacts.contacts)
            )
            json = serialize_model(read_contacts)

        session["contacts"] = json
        session["contacts_updated"] = True
        
        print("Contacts loaded successfully.")
        
    return redirect(request.referrer)


@app.route("/accounting_contact_read_one")
@xero_token_required
def accounting_contact_read_one():
    xero_tenant_id = 'a477f7c2-71d5-44ad-87bb-82ec85e2e62e'
    accounting_api = AccountingApi(api_client)

    try:
        read_contacts = accounting_api.get_contacts(
            xero_tenant_id
        )
        contact_id = getvalue(read_contacts, "contacts.0.contact_id", "")
    except AccountingBadRequestException as exception:
        output = "Error: " + exception.reason
        json = jsonify(exception.error_data)

    #[CONTACTS:READ_ONE]
    xero_tenant_id = 'a477f7c2-71d5-44ad-87bb-82ec85e2e62e'
    accounting_api = AccountingApi(api_client)

    try:
        read_one_contact = accounting_api.get_contact(
            xero_tenant_id, contact_id
        )
    except AccountingBadRequestException as exception:
        output = "Error: " + exception.reason
        json = jsonify(exception.error_data)
    else:
        output = "Contact read with id {} ".format(
            getvalue(read_one_contact, "contacts.0.contact_id", "")
        )
        json = serialize_model(read_one_contact)
    #[/CONTACTS:READ_ONE]

    return json

@app.route("/accounting_contact_read_one_by_contact_number")
@xero_token_required
def accounting_contact_read_one_by_contact_number():
    xero_tenant_id = 'a477f7c2-71d5-44ad-87bb-82ec85e2e62e'
    accounting_api = AccountingApi(api_client)

    try:
        read_contacts = accounting_api.get_contacts(
            xero_tenant_id
        )
        contact_number = getvalue(read_contacts, "contacts.0.contact_number", "")
    except AccountingBadRequestException as exception:
        output = "Error: " + exception.reason
        json = jsonify(exception.error_data)

    #[CONTACTS:READ_ONE_BY_CONTACT_NUMBER]
    xero_tenant_id = 'a477f7c2-71d5-44ad-87bb-82ec85e2e62e'
    accounting_api = AccountingApi(api_client)

    contact_number=contact_number

    try:
        read_one_contact = accounting_api.get_contact_by_contact_number(
            xero_tenant_id, contact_number
        )
    except AccountingBadRequestException as exception:
        output = "Error: " + exception.reason
        json = jsonify(exception.error_data)
    else:
        output = "Contact read with number {} ".format(
            getvalue(read_one_contact, "contacts.0.contact_number", "")
        )
        json = serialize_model(read_one_contact)
    #[/CONTACTS:READ_ONE_BY_CONTACT_NUMBER]

    return json



# TODO INVOICE
@app.route("/invoice_read_all")
@xero_token_required
def invoice_read_all():

    print("console output testing")
    #[INVOICES:READ_ALL]
    xero_tenant_id = 'a477f7c2-71d5-44ad-87bb-82ec85e2e62e'
    accounting_api = AccountingApi(api_client)

    try:
        invoices_read = accounting_api.get_invoices(
            xero_tenant_id
        )
    except AccountingBadRequestException as exception:
        output = "Error: " + exception.reason
        json = jsonify(exception.error_data)
    else:
        output = "Total invoices found:  {}.".format(len(invoices_read.invoices)
        )
        json = serialize_model(invoices_read)
    #[/INVOICES:READ_ALL]
    
    return json

    
@app.route("/invoice_read_one")
@xero_token_required
def invoice_read_one():
   
    xero_tenant_id = 'a477f7c2-71d5-44ad-87bb-82ec85e2e62e'
    accounting_api = AccountingApi(api_client)

    try:
        read_invoices = accounting_api.get_invoices(
            xero_tenant_id
        )
        invoice_id = getvalue(read_invoices, "invoices.0.invoice_id", "")
    except AccountingBadRequestException as exception:
        output = "Error: " + exception.reason
        json = jsonify(exception.error_data)

    #[INVOICES:READ_ONE]
    xero_tenant_id = 'a477f7c2-71d5-44ad-87bb-82ec85e2e62e'
    accounting_api = AccountingApi(api_client)

    try:
        read_one_invoice = accounting_api.get_invoice(
            xero_tenant_id, invoice_id
        )
    except AccountingBadRequestException as exception:
        output = "Error: " + exception.reason
        json = jsonify(exception.error_data)
    else:
        output = "Invoice read with id {} ".format(
            getvalue(read_invoices, "invoices.0.invoice_id", "")
        )
        json = serialize_model(read_one_invoice)
    #[/INVOICES:READ_ONE]

    return json
    
# TODO ITEM

@app.route("/accounting_item_read_all", methods=["GET", "POST"])
@xero_token_required
def accounting_item_read_all():
    
    if request.method == "POST":
        tenant_name = request.form.get("tenant_name_item")
        xero_tenant_id = None    
   
        for tenant_data in session.get("tenants", []):
            if tenant_data["tenantName"] == tenant_name:
                xero_tenant_id = tenant_data["tenantId"]
                break

        if xero_tenant_id is None:
            print("Tenant not found.")
            return redirect(request.referrer)

        accounting_api = AccountingApi(api_client)
        
        try:
            read_items = accounting_api.get_items(
                xero_tenant_id
            )
        except AccountingBadRequestException as exception:
            output = "Error: " + exception.reason
            json = jsonify(exception.error_data)
        else:
            output = "Items read {} total".format(
                len(read_items.items)
            )
            json = serialize_model(read_items)
            
        session["items"] = json
        session["items_updated"] = True
        
        print("Items loaded successfully.")
        
    return redirect(request.referrer)
     
     
    
if __name__ == "__main__":
    app.run(host='localhost', port=5000, debug = True)