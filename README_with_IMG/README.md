## XERO OAuth2 Functions

### 1. Environment Setup

 **Create the virtual environment and install dependencies**  
 **Run the code by `python app_func.py` using localserver port 5000**  
   
   ```bash
   virtualenv venv
   venv\Scripts\activate
   pip install -r requirements.txt

   python app_func.py
  ```

  NOTE: 
  the webhook cannot work with localserver, so install ngrok, right click the folder, enter CMD, and run the command as below. Please remember to replace the FORWARDING url into the XERO DEVELOPER-WEBHOOK 
  ![Alt text](image-2.png)
  ![Alt text](image-1.png)
  ![Alt text](image-3.png)
### 2. Main functionalities
As shown in the main page screenshot below, there are the main functionalities.
You can find the corresponding code of these functions by the links template/base.html
![Alt text](image.png)

### 3. TODOs and ISSUES PENDING TO SOLVE
You can find many TODOs in the code, which means more functions not done yet.

The current issus I am facing is about the WEBHOOK - READ - CREATE flow.

As I can achieve the functions below seperately
1. the webhook information retrieval (please find it in function webhook_receiver(), where I already get the xero_tenant_id and invoice_id)
2. Read invoice by its ID and given tenantID (as function read_invoice_one. The read_invoice_one_webhook is written for webhook but failed)
3. Create invoice

But, I cannot recieve the read_invoice_one_webhook message, the new invoice message, when webhook_receiver() is triggered, as shown below.
![Alt text](image-4.png)

I also tried to define the read function inside the webhook_reciever (commented off line 667-698), but there are more authentication errors I cannot solve...
![Alt text](image-5.png)

Since I am not connecting to the DB, and all the information are saved in session[](flask internal temp storage), I believe if connecting db, we can do more message reading or retireving seperately and bypass some xero api communication.

You may reference to invoice GET/POST from doc https://developer.xero.com/documentation/api/accounting/invoices



