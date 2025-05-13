# Tines SOAR EDR Project

## Objective

The Tines SOAR-EDR project aimed to establish an automated response in a controlled environment for quickly responding to detected cyber attacks. The primary focus was to ingest and analyze logs of an attacked computer within an Endpoint Detection and Response(EDR) system called LimaCharlie, generating telemetry to create a rule-based alert. This alert will then forward this data to the security orchestration, automation, and response(SOAR) tool Tines. Tines will then quickly send the details of this alert to an email, a Slack channel, and prompt an analyst to isolate this machine. If prompted to isolate, Tines forwards to command to LimaCharlie to instantly separate the computer from the network until further notice. This hands-on experience was designed to deepen understanding of network security, automation, and rule creation.

### Skills Learned

- Proficiency in Security Automation with Tines SOAR.
- Incident Response Planning and Execution.
- Ability to generate and recognize attack signatures and patterns.
- Development of scripting and Automation for Threat Mitigation.

### Tools Used

- Vultr, a cloud-based virtual machine service to spin up the infected computer.
- LimaCharlie Endpoint Detection and Response, to detect the infection and control isolating the machine.
- Tines SOAR, to manage the automation.
- Slack, to emulate a general SOC channel receiving the notifications.

## Steps

SOAR EDR project

Goal: To create a custom detection & response rule within LimaCharlie, and make a playbook that connects the resources Tines, Slack, Email, and has a response capability

Diagram:
![image](https://github.com/user-attachments/assets/3fac9aa7-a380-4e2f-904f-a03797280da5)

Playbook objective: 
Upon detection, it will send a slack message, and send an email containing info about the detection. This will include a user prompt asking to isolate the machine

Spcific goal of the playbook(called “Story” in Tines): 
1.	Create a detection in LimaCharlie – Detect Hacktool > Tines > Clack & Email
2.	Slack & Email will contain the time, the computer name, the source IP, the process, the command line, potentially the file path, sensor ID, link to the detection
3.	Tines > Prompt User to isolate the machine (Yes/No)
4.	If yes: LimaCharlie should automatically isolate the machine, and a message should be sent to Slack. The message should contain the isolation status with a note of “the computer <computer> has been isolated”
5.	If no: LimaCharlie will not isolate, still send a message to Slack stating “The computer <computer> was not isolated, please investigate”

Setup:
1.	Install and configure LimaCharlie
To complete this, we really just need an old computer that you can configure, and a comprehensive understanding of your firewall, to simplify the process, I have elected to use the cloud service vultr.com , and will be describing the process of setting up their cloud service for this project(If you are following my setup completely, in vultr under billing apply the code “FLY300VULTR” to get 300 credits for free for 30 days).
If following my setup completely, within vultr in the top right hover over “Deploy” and select “Deploy new Server”

![image](https://github.com/user-attachments/assets/429b033f-b851-4087-af8d-096f6be4e06d)

From there, under type select “Cloud Compute – Shared CPU”(you may have to select in the top right “Switch back to the old experience” to see the same window)

![image](https://github.com/user-attachments/assets/b467559b-80cd-4dd1-9082-29829b5e0817)

Under location pick the location closest to yourself. Under Image select Operating System > Windows Standard > Current version

![image](https://github.com/user-attachments/assets/e5aba301-8faf-435d-81f3-eba0e48b627e)

Under plan select Regular Cloud Compute > 55 GB SSD(This project does not require much out of this computer, which is why I am picking the lowest possible settings for affordability)

![image](https://github.com/user-attachments/assets/86ae4ab2-bb35-4d9d-8cf7-8068c12e01b4)

Under Additional Features select Auto Backups > I understand the ricks > Disable Auto Backups(normally a good idea, not needed for this project)

![image](https://github.com/user-attachments/assets/40af1b75-b21e-4579-9420-4fb460acf551)

and under Additional Features Select “IPv6” to turn it off. Your Additional features should all be shown as turned off like this:

![image](https://github.com/user-attachments/assets/6ec7e1a0-2838-41b9-86de-ef711ec09299)

Lastly, under Server Hostname, come up with a relevant Hostname and enter it, I went with “SOAR-EDR”

![image](https://github.com/user-attachments/assets/27684ca5-a552-4972-abbe-f826460b8d49)

Once you have set all of that, select “Deploy Now”, and wait for the server to finish being configured. You will know if it is finished once it shows the status “Running”

![image](https://github.com/user-attachments/assets/4b29485d-8e1f-493c-99d7-d2399aceee60)

While waiting for the server to be configured, The next step is to sign up for and configure LimaCharlie. Open a new tab and go to https://limacharlie.io/ , and choose sign up. Once you have entered in a valid email, it will ask you questions to describe your team/company. Fill these out however you wish, and then selec the checkbox for the terms of service, and hit  “Get Started”, and then “Create Organization”

![image](https://github.com/user-attachments/assets/92b8ec01-84a0-4bae-a809-7f2b8c7d1af4)

From here, you will be presented with a name to give to your organization, and a data residency region. Come up with an appropriate name and apply it top your Org, and for the region select the region closest to yourself. Once complete, select “Create Organization”

![image](https://github.com/user-attachments/assets/f7bb013e-1612-49e3-9a82-d267c00194cf)

Next, we will need to configure the firewall. In vultr, select the Network tab > Firewall, and then select “Add Firewall Group”

![image](https://github.com/user-attachments/assets/6ba742f9-979b-49f7-ae3e-e288fa49afcb)

From here, you will be prompted to create a name, come up with a name and select “Add Firewall Group”

![image](https://github.com/user-attachments/assets/19f02c84-b5a2-4a0c-802a-259a4154e585)

Next, update the default firewall rule to have the protocol “MS-RDP”, with the source set to “Custom”, and for the exact address add your computer’s IPv4 address (A simple way to locate this is with the website https://whatismyipaddress.com/ ), and finally select the plus button on the far right to add the firewall rule. When finished, it should look like so:

![image](https://github.com/user-attachments/assets/5047d45d-a191-4763-ad17-b6d55e04fdc8)

Next, to add the virtual machine to the firewall, select the “Compute” tab, select your machine, Select the settings tab at the top, on the new tab on the left select “Firewall”, and from the dropdown select the firewall you created, then hit “Update Firewall Group”

![image](https://github.com/user-attachments/assets/117bd86b-8469-4a5d-ba7b-e7802e471ac7)

Eventually, we will want to install LimaCharlie on our server, but due to the limited resources we will make most of the configuration on our host machine.
Back in LimaCharlie, on the left select Sensors > Installation Keys, and now on the right select “Create Installation Key”

![image](https://github.com/user-attachments/assets/70e738e1-f2d7-4025-a375-b07d42a6c827)

From here, set a name for the key in the description, and then select “Create”

![image](https://github.com/user-attachments/assets/f8bff13c-0368-4f82-991d-28d1a3e0d8e2)

Now that we have our installation key, we can install LimaCharlie onto our server. If following my setup, first remote into your vultr VM server. Vultr has a “View Console” button that will remotely connect you to the server, however if you are using a windows computer I recommend using the “Remote Desktop Connection” app

![image](https://github.com/user-attachments/assets/1df81e8e-49e4-4498-b87d-a2fb57c82571)

If prompted for the username and password credentials when connecting, you can locate that information in the “OverView” Tab of your server within Vultr:

![image](https://github.com/user-attachments/assets/0861c940-6f7f-4a4a-92c1-b53ef2f1f4ad)

Once connected to your server, navigate to Microsoft Edge and open a new window. Now go back to your host computer, and back to the LimaCharlie Installation keys tab. Scroll down to the Sensor Downloads section, right click the link for windows 64 bit(the OS for our server), and select “copy link”

![image](https://github.com/user-attachments/assets/17876672-c7bd-4f96-8ec7-275ab8109d33)

Now return to your remote connection to your vultr VM server, and paste the copied link into the Microsoft edge search bar. Depending on your remote settings, your clipboard might not be set up to transfer between a remote connection and your host computer. If so, you may simply choose to type in the following link: https://downloads.limacharlie.io/sensor/windows/64 . If completed successfully, you should now see the following exe file download:

![image](https://github.com/user-attachments/assets/06c602ea-df0b-45d3-b31f-6a009ff5372c)

Once downloaded, open up a PowerShell window as an administrator. First navigate to the downloads directory by entering the command “cd Downloads”. Once there, type in”.\hcp”, hit tab once to autofill the whole name of the downloaded exe, then after it type “-i”. Before continuing, go back to limacharlie on your host machine, and copy the sensor installation key:

![image](https://github.com/user-attachments/assets/dfbdb8dd-0b8e-443c-8784-a647441a7e56)

Once copied, go back to your remote connection, and paste the sensor key after “-I”. Once finished, your command should look something like this:

![image](https://github.com/user-attachments/assets/6f36af3c-6d46-45cd-83d6-b440924145a3)

Finally, hit enter. If performed properly, you should receive the following message:

![image](https://github.com/user-attachments/assets/4bac7f74-8e4b-4ec2-b3bc-1f83503e8d60)

2.	Setup noise and data for rule
Now that we have connected our server to LimaCharlie, we need to download a malicious tool to create data for us to monitor and make rules off of. For this project, I went with the LaZagne Project. Connect to your Windows server created earlier with your tool of choice(I will demonstrate using the windows Remote Desktop Connection tool).
Once connected, search up “Windows Security”, click on the “Virus & Threat Protection” box, and then under “Virus & Threat Protection Settings” click Manage settings > click on the slider under real-time protection to “off”

![image](https://github.com/user-attachments/assets/49baaa1f-eba0-4dd0-bfec-40a230520c1c)

![image](https://github.com/user-attachments/assets/09179b98-0813-4cba-8c1c-4c71d84dc920)

![image](https://github.com/user-attachments/assets/9810d63f-d1d8-4498-8a1e-c66030d0e81c)

Next, go to the github page for LaZagne, and download the latest release: https://github.com/AlessandroZ/LaZagne/releases 
Once it is finished downloading, you will likely receive warning messages like the following:

![image](https://github.com/user-attachments/assets/3b2ce5d5-5980-4ccd-9458-c2933a0123e4)

If this error happens, click on the ellipse next to the warning message, and select “Keep”

![image](https://github.com/user-attachments/assets/f2deba61-5a0b-475d-950d-012130ba27c3)

If you are given an additional prompt, select the “Show more” drop-down, and then select "Keep anyway”

![image](https://github.com/user-attachments/assets/0bf5f89d-5f7f-4b98-b8f1-2dad660ee2e3)

Once there are no more warnings for the downloaded file, we will need to run it in a powershell window for it to properly execute. A simple way to do this is to open up a File Explorer window and open your downloads folder. In the middle of the window, hold down the shift key and right-click the blank white spot in the middle, and from the dropdown select “Open PowerShell window here”

![image](https://github.com/user-attachments/assets/215ef1de-8dfc-4ce4-8fa6-2f25f60078fa)

Once the window is open, tytpe and enter “./LaZagne.exe”. If done correctly, LaZagne will list any passwords it detects

![image](https://github.com/user-attachments/assets/25a14bf5-4de4-4fda-becd-7c23017883cf)

To confirm that our sensor agent from LimaCharlie is configured correctly, head back over to LimaCharlie on your host computer, select your agent from the sensor list, and then within the sensor menu select the “Timeline” tab on the left.

![image](https://github.com/user-attachments/assets/ace7c819-8035-4a09-a522-760dc579ef50)

Once in the timeline menu, search for the term “lazagne”. If everything is set correctly, you should see a “NEW_DOCUMENT” event and a “NEW_PROCESS” event at the top of the search. We will be using these events to help create our detection rule.

![image](https://github.com/user-attachments/assets/befb2b87-3577-43a5-9f55-0de9722a1141)

To create this rule, for convenience sake open up LimaCharlie in another tab, and in this tab click the Automation drop down on the left, it will default to the D&R rules tab. In this new window, click the “Add Rule” button on the top right

![image](https://github.com/user-attachments/assets/429819c8-c453-4277-b850-eb6ba3194e34)

Normally it can help to look at similar rules to what you are trying to detect, and to view the documentation(https://docs.limacharlie.io/docs/detection-and-response) for making a rule, but in this case we will use a prebuilt rule from the author MyDFIR. In the Detect Field, copy and paste the following:
events:
  - NEW_PROCESS
  - EXISTING_PROCESS
op: and
rules:
  - op: is windows
  - op: or
    rules:
    - case sensitive: false
      op: ends with
      path: event/FILE_PATH
      value: LaZagne.exe
    - case sensitive: false
      op: contains
      path: event/COMMAND_LINE
      value: LaZagne
    - case sensitive: false
      op: is
      path: event/HASH
      value: '3cc5ee93a9ba1fc57389705283b760c8bd61f35e9398bbfa3210e2becf6d4b05'

In the response field, paste the following:

- action: report
  metadata:
    author: MyDFIR
    description: TEST - Detects Lazagne Usage
    falsepositives:
    - ToTheMoon
    level: high
    tags:
    - attack.credential_access
  name: MyDFIR - HackTool – Lazagne
Once you have added the rule data to both fields, set a name at the top and select “Create” in the bottom right corner:

![image](https://github.com/user-attachments/assets/4d6a7fd4-c2cf-421a-8872-d323b60ff572)

Once copied over, to test the rule we can tab back to the first tab we started at, select the “NEW_PROCESS” event pointed out earlier, and at the top right copy the event.

![image](https://github.com/user-attachments/assets/6dd3a67e-4ddb-43e5-bc53-5db8ef5bca0a)

Next, go back to the tab where we copied and pasted this new rule. Scroll down and select “Target Event”, in the blank field paste the event from before, and then at the bottom select “Test Event”. Provided everything has been done successfully, you should see a result “Match” at the bottom:

![image](https://github.com/user-attachments/assets/f246d7ae-8815-43d8-b664-e13566270618)

3.	Configure Slack and Tines
Go to Slack.com(https://slack.com/) and select Get Started

![image](https://github.com/user-attachments/assets/14fc2f22-e76e-4fd8-9c00-490a1d2ddf1b)

Enter in a valid email, and then once authenticated select “Create Workspace”. Follow the prompts on the screen to add a company/team name and setting a name for your account. When asked to invite other users, select “skip this step”

![image](https://github.com/user-attachments/assets/9afc73ca-931a-42bd-b3c1-0c4bc0394dd5)

If prompted to use the pro version of Slack, select the free version

![image](https://github.com/user-attachments/assets/63649ed4-c1b3-4ed5-a762-b6cd652783b9)

Once inside Slack, on the left pane select “Add channels”, and create a new channel called alerts. If prompted to share with others, skip sharing.

With Slack now set up, go over to https://www.tines.com/ and sign up using a valid email account. Once signed up, create a general name for a company for this project, and then hit “Next”

![image](https://github.com/user-attachments/assets/497f25d2-66cf-4c77-be99-4615f3dffa58)

Tines will then start giving you a walkthrough, you may either follow it with them or skip. Once past the walkthrough, Tines will take you to it’s general story menu. If the app has any placeholder or starter tools placed on this screen, clear them out by left clicking them, then clicking the trashcan icon on their bar to delete them.

![image](https://github.com/user-attachments/assets/2ea9dad0-cf55-4433-927f-7daa6bdf6b95)

After clearing the tools, click and drag over a Webhook tool, and on the right pane rename the tool to “Detection”, in the description add “Gathers LimaCharlie Detections”, and copy the webhook URL. Go back to LimaCharlie, on the left select Outputs > Add Output

![image](https://github.com/user-attachments/assets/19ae0822-a7e3-4f7d-9436-baa6f8f0d612)

On the new pop-up menu, select Detections > Tines, type in an appropriate name, and then for the Destination host paste in the Tines webhook URL, then hit “Save Output”

![image](https://github.com/user-attachments/assets/de290b12-4a51-4340-99b5-33cc5b7ec99c)

Now that we’ve linked LimeCharle to Tines, we need to connect Slack as well, so that the alerts will reach it. In Slack, on the left column select the ellipse > Automations

![image](https://github.com/user-attachments/assets/ae4f8980-4ec6-4b76-9ae3-decb4f3d5f5e)

In the new Automations tab, select Apps, and then search in the search bar at the top for Tines, and on the app select Add

![image](https://github.com/user-attachments/assets/a194a040-334b-4f84-afcf-07be59d25aa6)

This will open up a new tab in the Slack Marketplace. In this new window, simply select “Add to Slack”

![image](https://github.com/user-attachments/assets/953644a1-b39b-4d83-960c-684b34e9aa84)

Slack will then redirect you to a new page where it will describe how to link the 2 tools together. This may vary depending on how old this guide is for the person reading it, but for myself it asks to add Slack to Tines by adding the credential within Tines. Specifically, in Tines go to your “dashboard” or “personal” window. If you are where this guide left off in the story tab, in the top left click “Personal”

![image](https://github.com/user-attachments/assets/94f2d301-6cf8-447d-8f42-477c384c5e4d)

In the personal window, select the word personal again on the top left, and from the drop down select “Credentials”

![image](https://github.com/user-attachments/assets/9d525202-a113-4d2e-971e-17c7cce7dc80)

In the credentials menu, select “New”, scroll down until you see Slack, and then select it

![image](https://github.com/user-attachments/assets/5c845ee5-6804-4f2f-95b8-dd081789ba9b)

This will open a new pop-up window. If prompted to “Use my own Slack app” or “Use Tine’s app for Slack”, select the option to use Tine’s version. If prompted, select allow to grant Tines permission to use Slack.

![image](https://github.com/user-attachments/assets/3a59679b-1928-4895-b201-a608c83e8e8a)

![image](https://github.com/user-attachments/assets/33c022a6-bc64-4ffb-b8a3-1e2c618e2063)

This should now successfully connect our Slack and Tines together. Next, return to your “story” view within Tines, on the left panel select Templates, and drag out Slack onto the story pane

![image](https://github.com/user-attachments/assets/e3069140-05c2-42e2-9f47-9bed05a1ffed)

We want to send a message to Slack every time LimaCharlie detects malware from one of its rules. To do this, select the Slack template added to the story pane, and now on the right pane search for “message” and from the results select “Send a message”

![image](https://github.com/user-attachments/assets/b4eb5e06-8df4-4c0e-8320-4ad42b0bfa8e)

In order to send a message, Tines will need the channel ID of the Slack Channel it is ending messages to. Return to Slack, and in your home menu right click alerts > click “View channel details” 

![image](https://github.com/user-attachments/assets/f3e76f85-5894-4e21-8a00-14b2405abd5b)

From here, it will list the channel ID at the bottom. Copy this ID, and then go back into Tines and paste it in the pane on the right. Leave the default message for now as a test. Once finished, hover over the Webhook icon, and a downward arrow should appear. Click and drag this arrow to the Slack object to connect it:

![image](https://github.com/user-attachments/assets/e00eeed1-b212-40de-b550-9e995972444b)

Once connected, click on the Slack icon, and from the new menu select “Run”

![image](https://github.com/user-attachments/assets/410d4db4-001d-4430-9629-6b9190707258)

If working properly, if you now check inside of Slack, you should now see the dialog “Hello world!” in the alerts channel:

![image](https://github.com/user-attachments/assets/3fad87de-2fe6-4bd7-b8ab-9ef2c23cdbfd)

Next, let’s add the function of sending an email. Go back into tines, and drag over the “Send Email” object from the left pane into the main window, and then drag the arrow from the webhook to the email action to connect the two.

![image](https://github.com/user-attachments/assets/cdceb11e-d65f-46d0-8a07-1c9126a75cb4)

Now select the Send Email object, and on the pane on the right set the sender name to Alerts, and the subject line to Test. The object will default to sending an email to the email account you signed up to Tines with, change this if you want to use a different email.

 In order to test the email function, we first need to send data to our webhook for it to use. In order to do this, log back into your remote server, and re-run LaZagne from a powershell window. After a few minutes, you should see a notification icon on the top right of your webhook object(you may have to refresh the Tines page for it to show), and an alert message should have been sent to your Slack, as well as an email sent to the mailbox you added to the email object:
(My screenshot has 2 notifications as I ran LaZagne twice by mistake)

![image](https://github.com/user-attachments/assets/c6f4f46c-03ab-4150-80be-c2e84dc55bfa)

![image](https://github.com/user-attachments/assets/30061d13-63d8-4201-a365-9315cb8279c1)

![image](https://github.com/user-attachments/assets/afe10569-5114-4210-a642-44b973c211dd)

Now that we have set up the initial responses, we want to give the end user the prompt to isolate this computer or not. We will do this using Tine’s “Page” tool. Go back into Tines, and on the left pane select the “+” tools icon, and then click and drag the “Page” icon onto the main window.

![image](https://github.com/user-attachments/assets/6a194720-8526-42d1-a0d9-0ed3a6912a65)

Now, select your page action, and on the panel on the right set the name to “User Prompt” for clarity. Now drag the arrow from the webhook to the page tool to link them together like so:

![image](https://github.com/user-attachments/assets/73f2e438-e601-4f46-bc62-0b0b783df7f2)

Before adjusting the page, we need to get Tines to recognize the info about our computer in the webhook, in order for it to show that info in the isolate dialog page. To do this, click on your webhook, select “Events” from the menu that appears below the icon, and from the new menu that appears at the bottom of the window click on the icon or ellipse to see the full detection details:

![image](https://github.com/user-attachments/assets/d54b9c6a-aa6b-4db5-9d3c-10d41ba89b1a)

As noted in the diagram for this project, we want to have the user prompt provide the end user with the time of the event, the computer name, the source IP, the process, the command line entered(if any), the file path, the sensor ID, the username, and a link to the detection rule used. To gather this data, have open an app you can paste info into like notepad, and in the bottom pane on Tines expand detection > body > and copy the value of the “cat” field. Next under body expand detect > event > and copy the path of the “COMMAND_LINE”. Back in the body section copy the path of the “Link” field. Then under body > detect > routing copy the path to “hostname”,  “evnt_time”,  “int_ip”., and “sid”. Lastly go back to detect > event and copy the path of “FILE_PATH” and “USER_NAME”. Once finished, the paths you have copied should look something like this:

![image](https://github.com/user-attachments/assets/fdf4d6cd-ec5b-44c3-b741-d883979fa6c4)

To represent the data in a more organized way, we want to change around the JSON paths so that it displays the Title, time of the event, computer name, computer IP, the user name, the path to the file, the command line used, the sensor ID, and lastly the link to the detection used. To do this, change the JSON paths so they are listed as so:

![image](https://github.com/user-attachments/assets/e34ccdc4-137a-4750-b315-c4c8207e558f)
 
To test this configuration, click on your Slack icon, on the pane on the right delete the info in the message field and paste in the JSON paths organized above, then select “Test” below the Slack icon in the middle, on the next menu select your previous event, then click the “Test” button on the bottom right.

![image](https://github.com/user-attachments/assets/53018868-de9f-451a-a514-f7221bdb330e)

![image](https://github.com/user-attachments/assets/142eb1f0-34bb-4138-9f3a-a95ef954c4f9)

![image](https://github.com/user-attachments/assets/b99221ae-28b6-4155-b91d-a9883687519b)

If everything is set correctly, if you now check the alert channel in slack you should see all of the data from the JSON paths that were copied:

![image](https://github.com/user-attachments/assets/f6827e29-6a62-4969-bddb-431715af0d3b)

To make this a bit cleaner for the end user, add titles for each of the JSON paths, like so:

![image](https://github.com/user-attachments/assets/b1a41537-17f3-4f01-81f4-dc7e1f5fc8af)

Add those titles to the data for the Slack message, and if you test with the same data it should update to the following:

![image](https://github.com/user-attachments/assets/7ea0a2cf-9954-4df5-85a7-dba0d22add4b)

Take this same data, and select the “Send Email” object in Tines, and on the right pane paste it into the “Body” field like so:

![image](https://github.com/user-attachments/assets/012d0c97-022e-4cfb-a92c-6707abe47ef8)

If we now test the email action with the same event, we see a puzzling result in the email:

![image](https://github.com/user-attachments/assets/62d5dcb3-c94d-48de-bf99-077decb76e35)

This is because the email is sending the data in HTML, and will not normally recognize our new lines without making further edits. To correct this, go back to Tines, select the “Send Email” object, and on the right pane next to the “Body” field click the up arrow to access the HTML editor:

![image](https://github.com/user-attachments/assets/2c45e8c0-8e8a-47c7-b501-c562f1f4ee28)

To have each line recognized properly, add the tag "(br)" after the first line, like so:

![image](https://github.com/user-attachments/assets/f4da3022-68b1-4ca7-ada3-575b6f057e58)

If we now run another test, the text should be listed in a much more readable manner:

![image](https://github.com/user-attachments/assets/cbeab2a5-8331-401b-8722-265a98d62c60)

Now that we have our prompting data set, let’s update the user prompt. click on the “User Prompt” page, and at the bottom right select “edit Page”. Change the heading to something other than the default text(I put the name of this project), and in the content dialog box change the text to “Do you want to isolate this machine?”. To give this page the ability to choose an option, on the left pane scroll until you see the “Boolean” input field, and drag it underneath the body text like so:

![image](https://github.com/user-attachments/assets/45fd5106-54fb-44f3-8c9b-56cb64cffae0)

Next, click on the Boolean item added, and on the right pane change the name to “Isolate”. Additionally, to add the data of the detection to the prompt, change the above field to the text 
<br>“Title: <<detection.body.cat>>
<br>Time: <<detection.body.detect.routing.event_time>>
<br>Computer: <<detection.body.detect.routing.hostname>>
<br>Source IP: <<detection.body.detect.routing.int_ip>>
<br>Username: <<detection.body.detect.event.USER_NAME>>
<br>File Path: <<detection.body.detect.event.FILE_PATH>>
<br>Command Line: <<detection.body.detect.event.COMMAND_LINE>>
<br>Sensor ID: <<detection.body.detect.routing.sid>>
<br>Detection Link: <<detection.body.link>>

Do you want to isolate this machine?”. 
<br>This will show all of the data in a readable format.
To add the yes or no functionality, return to your main story page in Tines, drag over a “Trigger” object from the left pane, rename it to “No”, and connect it to the user prompt, like so:

![image](https://github.com/user-attachments/assets/759e6b88-03f5-407b-8a90-59be36d1538d)

Before we can properly configure the yes and no triggers, we need event data of the user prompt running. Click on the “User Prompt” object, and select the arrow to visit the page:

![image](https://github.com/user-attachments/assets/db8006bd-bbfc-4336-af4b-539230aced16)

If prompted to select a recent event, select any one of them, and you should be brought to the dialog box we have created. Select the “No” option and then hit submit. Once finished, exit out of the user prompt window, and select the “no” trigger. On the right pane, delete the info in the rules tab, and enter into the field “<<user_prompt.body.isolate>>”. Below it under “is equal to”, delete anything in the field and set it to false, like so:

![image](https://github.com/user-attachments/assets/0d2245fe-c210-434c-9fbf-5929f6a0eac9)

Next, click on the Slack icon from earlier, select “copy” on it’s menu and then press ctrl+v below the trigger to paste it. Select the copied slack item and on the right pane delte the info on the message field, and set the message to “The computer "<<detection.body.detect.routing.hostname>>" was not isolated, please investigate.”. Lastly, connect the trigger “No” to this new Slack item. If tested by re-emitting one of the events from the webhook, the Alerts channel will successfully display the message like so:

![image](https://github.com/user-attachments/assets/d728ebc3-0d2f-48f4-b846-513437958f1a)

Now, to create the response for the user selecting “Yes” in the user prompt, we first need data of “yes” being selected. First select the “No” trigger, press ctrl+c to copy, and press ctrl_v to duplicate it on the screen. Rename this duplicate trigger to “Yes”. Connect this trigger to the User Prompt. Next click on the Webhook, from the dropdown menu select events, and on the last event select “Re-emit”

![image](https://github.com/user-attachments/assets/1eaa1cda-5e70-45cf-b48d-88baa40ec71a)

Next click on User Prompt, select visit page, and select the most recent event:

![image](https://github.com/user-attachments/assets/cc8c7d7e-994e-4fe6-a1b5-ae016c7d9699)

This time, in the prompt select “yes" on isolate, and then submit. Now return to Tines and select the “Yes” trigger. In the Rules section change the “is equal to” field to true.

![image](https://github.com/user-attachments/assets/fa99cd19-4718-4a6b-a2fb-90e760aeb01a)

Next, in the left pane Select templates, and search for LimaCharlie, and then drag it onto the main window. Once added, select the LimaChalie object, and on the right select the “Isolate Sensor” build:

![image](https://github.com/user-attachments/assets/b95ca1b4-e6b0-4e16-9279-fbe2ed0280b4)

Next, on the right pane, under the URL delete the current information and paste “https://api.limacharlie.io/v1/<<detection.body.detect.routing.sid>>/isolation”.
In order for Tines to communicate with LimaCharlie and isolate a computer, it needs credential information as well. Open a new tab in tines, go to your personal tab, and select Personal > Credentials

![image](https://github.com/user-attachments/assets/658ef298-780f-4cbf-bbe9-80b430ed8549)

In the credentials menu select New > Text to create a new general credential. Then move over to LimaCharlie, navigate to Access Management > REST API, and copy your Org JWT:

![image](https://github.com/user-attachments/assets/7ccbcebb-e4fe-40c3-8d84-0c538f8f2453)

Create a new Text credential, name it something appropriate like “LimaCharlie”, under the Value section paste the JWT from LimaCharlie, and under domains enter in “*.limacharlie.io”. This ensures that this key is only used with LimaCharlie specifically. Lastly, hit save to save this credential.

Now return to the story panel, and on the right pane there should be a Credentials section. Click “Connect” next to lima_charlie, and select the credential we just created.

![image](https://github.com/user-attachments/assets/fe883ea0-05fc-4566-936d-6d286894b075)

From here, we need to have a message sent to Slack when a machine is isolated from the network. On the left pane Select Template > LimaCharlie, and in the new template item choose the build “Get Isolation status”:

![image](https://github.com/user-attachments/assets/9983451d-0555-4e99-9035-43bad9d8e27f)

In the new Get Isolation Status URL, change the URL to https://api.limacharlie.io/v1/<<detection.body.routing.sid>>/isolation. Connect this item to the Isolate Sensor item, like so:

![image](https://github.com/user-attachments/assets/ecf93c67-1c3c-4819-b045-46a27c0b1cdb)

Next, click on of the blank spaces in the space, and on the right pane there should be a Credentials section. For the third connection select Connect > LimaChalie, to have it use the credential we configured earlier.

![image](https://github.com/user-attachments/assets/1118d981-c678-4d92-805c-a54d3c86494c)

Lastly, copy one of the Slack objects created earlier, and paste it below the  “Get Isolation Status” item. In the new Slack object, change the message to “Isolation Status:<<get_isolation_status.body.is_isolated>>
The computer "<<detection.body.detect.routing.hostname>>" has been isolated.”
Finally, connect this Slack object to the “Get Isolation Status” HTTP request.

And with that the project is complete! When LimaCharlie detects any alert, it sends a Slack message and email containing the user information, as well as asking to isolate the machine or not. If “yes” is selected, the machine is isolated using LimaCharlie, and a message is sent to the Slack channel to notify the change. If “No” is selected, a message is sent to Slack advising that the PC be investigated.
