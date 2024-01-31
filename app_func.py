import os
import time
import dateutil.parser
import re
import mimetypes

from dateutil.parser import parse
# from datetime import datetime, timedelta
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
# DONE fetch config from https://identity.xero.com/.well-known/openid-configuration #1
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
    scope = 'openid email profile offline_access accounting.transactions accounting.settings accounting.contacts accounting.transactions.read',
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
    
# DONE AUTHORIZE with ORGANIZATIONS
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


# DONE TENANTS
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



# DONE CONNTACTs

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
            json_rlt = jsonify(exception.error_data)
        else:
            output = "Contact(s) read {} total".format(
                len(read_contacts.contacts)
            )
            json_rlt = serialize_model(read_contacts)

        # print(json_rlt)   # DELETE
        
        # NOTE: same contact in different ORGANIZATION has DIFFERENT ID
        # TODO: in this case, when initializtion, need to do contact_read_all for EACH TENANTS????  (or DB initialization)
        # TODO: AUTO CONTACT CREATION if a contact if not exist in an organization
        session_name = "contacts_" + tenant_name
        session[session_name] = json_rlt
        session["contacts_updated"] = True
        
        print("Contacts loaded successfully.")
        
    return redirect(request.referrer)

# REVIEW CONTACTS - HOW FETCH CONTACTS????
#       Either: 1. read all, store in db (session[contacts] for now),
#                  fetch contactID by name
#               2. read one by one by accounting_contact_read_one[not done yet]
def find_contact_id_by_name(read_contacts, contact_name):
        for index, data in enumerate(read_contacts.contacts):
            contact_name_temp = getvalue(read_contacts, "contacts."+ str(index) + ".name", "")   
            print(contact_name_temp)
            if contact_name_temp == contact_name:
                contact_id = getvalue(read_contacts, "contacts."+ str(index) + ".contact_id", "")
                print("contact_id recieved")
                return contact_id
        return None


# @app.route("/accounting_contact_read_one_by_contact_number")
# @xero_token_required
# def accounting_contact_read_one_by_contact_number():
#     xero_tenant_id = 'a477f7c2-71d5-44ad-87bb-82ec85e2e62e'
#     accounting_api = AccountingApi(api_client)

#     try:
#         read_contacts = accounting_api.get_contacts(
#             xero_tenant_id
#         )
#         contact_number = getvalue(read_contacts, "contacts.0.contact_number", "")
#     except AccountingBadRequestException as exception:
#         output = "Error: " + exception.reason
#         json = jsonify(exception.error_data)

#     #[CONTACTS:READ_ONE_BY_CONTACT_NUMBER]
#     xero_tenant_id = 'a477f7c2-71d5-44ad-87bb-82ec85e2e62e'
#     accounting_api = AccountingApi(api_client)

#     contact_number=contact_number

#     try:
#         read_one_contact = accounting_api.get_contact_by_contact_number(
#             xero_tenant_id, contact_number
#         )
#     except AccountingBadRequestException as exception:
#         output = "Error: " + exception.reason
#         json = jsonify(exception.error_data)
#     else:
#         output = "Contact read with number {} ".format(
#             getvalue(read_one_contact, "contacts.0.contact_number", "")
#         )
#         json = serialize_model(read_one_contact)
#     #[/CONTACTS:READ_ONE_BY_CONTACT_NUMBER]

#     return json



# DONE INVOICE READ ALL
@app.route("/invoice_read_all", methods=["GET", "POST"])
@xero_token_required
def invoice_read_all():

    if request.method == "POST":
        tenant_name = request.form.get("tenant_name_invoice_read")
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
            invoices_read = accounting_api.get_invoices(
                xero_tenant_id
            )
        except AccountingBadRequestException as exception:
            output = "Error: " + exception.reason
            json_rlt = jsonify(exception.error_data)
        else:
            output = "Total invoices found:  {}.".format(len(invoices_read.invoices)
            )
            json_rlt = serialize_model(invoices_read)
            
        # session["invoices"] = json
        # session["invoices_updated"] = True
        
        print("Invoices loaded successfully.")
        
    return redirect(request.referrer)


# # DONE invoice read one     
@app.route("/invoice_read_one", methods=["GET", "POST"])
@xero_token_required
def invoice_read_one():
    
    print("enter invoice read function")

    if request.method == "POST":
        tenant_name = request.form.get("tenant_name_invoice_read_one")
        xero_tenant_id = None    
   
        for tenant_data in session.get("tenants", []):
            if tenant_data["tenantName"] == tenant_name:
                xero_tenant_id = tenant_data["tenantId"]
                break

        if xero_tenant_id is None:
            print("Tenant not found.")
            return redirect(request.referrer)
    
        accounting_api = AccountingApi(api_client)
        invoice_id = "35edb081-0b26-4254-a2ab-df27474ac687"

        try:
            print("flag1")
            read_one_invoice = accounting_api.get_invoice(
                xero_tenant_id, invoice_id
            )
            
        except AccountingBadRequestException as exception:
            output = "Error: " + exception.reason
            json = jsonify(exception.error_data)
            return jsonify(exception.error_data), 400
        else:
            output = "Invoice read with id {} ".format(invoice_id)
            json_file = serialize_model(read_one_invoice)
            print(json_file)
            # session['invoicetest'] = json 
            print("Invoices loaded successfully.")
            
    return redirect(request.referrer)


# TODO invoice_read_one for webhook
@xero_token_required
def read_invoice_one_webhook(tenant_id, invoice_id):
    
    accounting_api = AccountingApi(api_client)

    try:
        new_token = api_client.refresh_oauth2_token()
    except Exception as e:
        print(f"Error refreshing token: {e}")
        return "error1"

    try:
        read_one_invoice = accounting_api.get_invoice(tenant_id, invoice_id)
    except AccountingBadRequestException as exception:
        print("Error: " + exception.reason)
        print(jsonify(exception.error_data))
        return "error2"
    else:
        output = "Invoice read with id {} ".format(invoice_id)
        json_rlt = serialize_model(read_one_invoice)
        return json_rlt
    


# TODO INVOICE CREATION:  mannul
# reference doc: https://developer.xero.com/documentation/api/accounting/invoices
@app.route("/invoice_create", methods=["GET", "POST"])
@xero_token_required
def invoice_create():

    if request.method == "POST":
        
        # 1. Get tenant_id
        tenant_name = request.form.get("tenant_name_invoice_creation")
        xero_tenant_id = None    
        for tenant_data in session.get("tenants", []):
            if tenant_data["tenantName"] == tenant_name:
                xero_tenant_id = tenant_data["tenantId"]
                break   
        
        accounting_api = AccountingApi(api_client)    
        
        # 2. Get contact_id
        contact_id = None
        try:
            read_contacts = accounting_api.get_contacts(
                xero_tenant_id
            )
        except AccountingBadRequestException as exception:
            output = "Error: " + exception.reason
            json_rlt = jsonify(exception.error_data)     
        # print(read_contacts)   
        contact_name = request.form.get("contact_name_invoice_creation")
        for index, data in enumerate(read_contacts.contacts):
            contact_name_temp = getvalue(read_contacts, "contacts."+ str(index) + ".name", "")   
            if contact_name_temp == contact_name:
                contact_id = getvalue(read_contacts, "contacts."+ str(index) + ".contact_id", "")
                print("contact_id recieved")
                break
        if contact_id == None:
            print("Contact not found.")
            return redirect(request.referrer)         
        
        
        # REVIEW in practice, lineitem & contact & accounts are all required
        #        if target tenant dont have any, need to create and update DB

        
        where = "Type==\"SALES\"&&Status==\"ACTIVE\""
        try:
            read_accounts = accounting_api.get_accounts(
                xero_tenant_id, where=where
            )
            # OPTIMIZE STATE ACCOUNTING ID instaed of get defualt one
            account_id = getvalue(read_accounts, "accounts.0.account_id", "")
        except AccountingBadRequestException as exception:
            output = "Error: " + exception.reason
            json_rlt = jsonify(exception.error_data)

        accounting_api = AccountingApi(api_client)

        contact = Contact(
            contact_id=contact_id
        )

        # OPTIMIZE STATE ACCOUNTING ID instaed of get defualt one
        line_item = LineItem(
            account_code=account_id,
            description= "Consulting",
            quantity=1.0,
            unit_amount=10.0,
        )

        # OPTIMIZE input date and due_date instead of default
        invoice = Invoice(
            line_items=[line_item],
            contact=contact,
            date= dateutil.parser.parse("2024-01-03T00:00:00Z"),
            due_date= dateutil.parser.parse("2024-02-01T00:00:00Z"),
            type="ACCREC"
        )

        invoices = Invoices(invoices=[invoice])

        try:
            created_invoices = accounting_api.create_invoices(
                xero_tenant_id, invoices=invoices
            )
        except AccountingBadRequestException as exception:
            output = "Error: " + exception.reason
            json_rlt = jsonify(exception.error_data)
        else:
            output = "New invoices status is '{}'.".format(
                getvalue(created_invoices, "invoices.0.status", "")
            )
            json_rlt = serialize_model(created_invoices)
            print(output)
            print(json_rlt)
            print("check new invoice status ----------------------------")
    return  redirect(request.referrer)


# TODO invoice creation: for WEBHOOK



  
# DONE ITEM

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
            json_rlt = jsonify(exception.error_data)
        else:
            output = "Items read {} total".format(
                len(read_items.items)
            )
            json_rlt = serialize_model(read_items)
        
        # print(json)
        
        # session["items"] = json
        # session["items_updated"] = True
        
        print("Items loaded successfully.")
        
    return redirect(request.referrer)
     
     
# TODO WEBHOOKs
webhook_key = app.config["WEBHOOK_KEY"]
 
@app.route('/webhooks', methods=['POST'])
def webhook_receiver():

    print("")
    print("receiving webhook: -------------------------------------------------------")
    req_body = request.data
    req_signature = request.headers.get('X-Xero-Signature')

    parsed = json.loads(req_body)
    # print(json.dumps(parsed, indent=4))
    print(req_signature)

        
    if verify_webhook_signature(req_body, req_signature):
        print("Webhook event received!")
        print("response status 200")
        print("ready for read new invoice")
        
        try:
            event_type = parsed.get('events')[-1].get('eventType')
            tenant_id = parsed.get('events')[-1].get('tenantId')
            resource_id = parsed.get('events')[-1].get('resourceId')
        except Exception as e:
            return Response(status=200)
        
        print(parsed.get('events')[-1])
        print("event ")
        print(event_type)
        print("tenant ")
        print(tenant_id)
        print("resource ")
        print(resource_id)
        
        session['webhook_info'] = {
            "eventType": event_type,
            "tenantID": tenant_id,
            "resourceID": resource_id
        }
        
        # REVIEW define the read and create function inside webhook reciever
        #        or will it be better to seperate them 
        # TODO   flow2: update invoice
        
        # DONE   auto create new invoice
        #        HERE should only be CREATE only, UPDATE is only used for testing
        if event_type == "CREATE" or event_type == "UPDATE":
        #   return redirect(url_for('invoice_read_one', invoice_id=resource_id))
            
            print("start read the newly-created invoice --------------")
            xero_tenant_id = session['webhook_info']['tenantID']
            invoice_id = session['webhook_info']['resourceID']
            print("xero_tenant_id and invoice_id")
            print(xero_tenant_id)
            print(invoice_id)
            
            rlt = read_invoice_one_webhook(xero_tenant_id, invoice_id)
            print("here is the reading rlt -----------")
            print(rlt)
            # accounting_api = AccountingApi(api_client)

            # try:
            #     new_token = api_client.refresh_oauth2_token()
            # except Exception as e:
            #     print(f"Error refreshing token: {e}")

            # # proceed with the API call
            # try:
            #     read_one_invoice = accounting_api.get_invoice(xero_tenant_id, invoice_id)
            # except AccountingBadRequestException as exception:
            #     output = "Error: " + exception.reason
            #     json_rlt = jsonify(exception.error_data)
            #     return jsonify(exception.error_data), 400
            #     # xero_token = obtain_xero_oauth2_token()
            #     # new_token = api_client.refresh_oauth2_token()
            # else:
            #     output = "Invoice read with id {} ".format(invoice_id)
            #     json_rlt = serialize_model(read_one_invoice)
            #     print("Here is the new invoice-------------------------------")
            #     print(json_rlt)
            #     session['invoice_new'] = json_rlt 
            #     print("Invoice read ends -------------------------------------")
            
            print("start create the invoice --------------")    
            # # TODO choose the correct xero-tenant 

        
    
        
        return Response(status=200)
    
    else:
        print("Webhook event rejected!")
        print("response status 401")
        print("")
        return Response(status=401)

def verify_webhook_signature(request_body, signature_header):

    print("in verify_webhook_signature")

    computed_signature = hmac.new(webhook_key.encode('utf-8'), request_body, hashlib.sha256).digest()
    computed_signature_base64 = base64.b64encode(computed_signature).decode('utf-8')

    if signature_header == computed_signature_base64:
        print('Signature passed! This is from Xero!')
        return True
    else:
        # If this happens, someone who is not Xero is sending you a webhook
        print('Signature failed. Webhook might not be from Xero or you have misconfigured something...')
        print(f'Got {computed_signature_base64} when we were expecting {signature_header}')
        return False   
   
 
if __name__ == "__main__":
    app.run(host='localhost', port=5000, debug = True)