# Multi User Blog
A multi user blog web application running on Google App Engine written in 
Python 2.7. Done as a part of Full-Stack Web Developer Nanodegree by Udacity.
  
## Introduction
This project can be used as a basis for multi user blog web application. It 
is founded on a Google App Engine which is a Google's cloud computing service
comming with data storage facilities. It is written in Python 2.7.

The project provides following features:
  * multiple user accounts
  * users can create content (blog posts)
  * users can edit their blog posts 
  * users can click like button under another users blog post
  * likes counter under blog posts
  * likes can be removed by clicking unlike
  * users can comment under any blog post
  * comments can be deleted
  * comments can be edited

## How to run it?

##### Install python 2.7
If you are on macOS or linux it is probably already installed. If it isn't 
use package manager of choice `apt`, `brew`, or what suits your needs.

The following line shows how python can be installed on Ubuntu 16.04.
  
````shell
sudo apt install python 
````

##### Instal Google App Engine SDK
Go to [SDK for App Engine Download site](https://cloud.google.com/appengine/docs/standard/python/download) 
and follow the 2 mentioned steps:
 
  * Download, install, and initialize the Cloud SDK
  * Install the gcloud component that includes the Python extension

The third (optional) step is not required. 


##### Clone the repository
Clone the git repository of this project form github. Did I mentioned that 
`git` is needed? If you don't have it on your machine install it with `apt`.
```shell
git clone https://github.com/halicki/3-multi-user-blog.git
cd 3-multi-user-blog
```

##### Install all requirements
Multi User Blog is dependent on a newer Jinja2 package than those available in 
Google App Engine. Fortunately those can be uploaded from your local machine.
Use `-t lib` command line parameter for `pip` (the Python package manager) to
store them in a `lib` directory. A line in `appengine_config.py` file points 
to the lib directory: `vendor.add('lib')`.
```shell
pip install -t lib -r requirements.txt
```

##### Sign Up for a Google App Engine Account.
Go to [Google App Engine singup page](https://console.cloud.google.com/appengine/)
and register yourself. 

##### Create a new project in Google’s Developer Console using a unique name.
Go to [Google's Developer Console](https://console.cloud.google.com/) and create
a new application.

##### Init your gcloud settings
Run this command to prime your google cloud tools.  
```shell
gcloud init
```

##### Deploy this app ON THE CLOUD...
Using `gcloud` tool send all project files up to the cloud.
```shell
gcloud app deploy
gcloud app browse
```

##### ... or run locally
Instead of previous step you can also run the app locally using the 
`dev_appserver.py` command (installed with SDK for App Engine).
```shell
dev_appserver.py .
```

## License

The code of the project can be redistributed in accordance to MIT License.