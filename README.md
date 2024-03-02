# Django Donation System

The Django Donation System is a secure and reliable platform that allows users to make donations using an OTP-based authentication system. It provides users with the capability to view their donation history and integrates a payment gateway for processing donations.

## Features

- **Authentication:** Secure login with OTP verification using the user's phone number.
- **Donation Processing:** Users can donate through a secure online payment gateway integration.
- **Payment History Management:** Users can view their past donation history, ensuring transparency and trust.
- **Data Visualization:** Monthly payment dashboard for users to analyze their donation patterns over time.
- **Dockerization:** The application is containerized with Docker, enabling easy deployment.

## Prerequisites

- Docker

## Setting Up the Project

1. Clone the repository:

cd your_project_directory

2. Create a `.env` file at the root of the project and populate it with the necessary credentials:

# SECRET KEY
SECRET_KEY='django-insecure-au@_s)zrb5fuan-bxdk4)f!k^#y6wrm8n61$2a--gw)%zy-k3='

# DATABASE
DATABASE_NAME=''
DATABASE_USER=''
DATABASE_PASSWORD=''
DATABASE_HOST='localhost'
DATABASE_PORT='5432'

MAX_TIME_LIMIT_TO_VERIFY_OTP='3'

TWILIO_ACCOUNT_SID=''
TWILIO_AUTH_TOKEN=''
TWILIO_PHONE_NUMBER=''

# Stripe Configuration
CURRENT_MODE="test" # test/live
TEST_STRIPE_SECRET_KEY_AYO=""
TEST_STRIPE_PUBLIC_KEY_AYO=""
LIVE_STRIPE_SECRET_KEY_AYO=""
LIVE_STRIPE_PUBLIC_KEY_AYO=""

TEST_STRIPE_SUCCESS_URL=''
TEST_STRIPE_CANCEL_URL=''
LIVE_STRIPE_SUCCESS_URL=''
LIVE_STRIPE_CANCEL_URL=''
TEST_STRIPE_WEBHOOK_SECRET=''
LIVE_STRIPE_WEBHOOK_SECRET=''

USE_DOCKER='true'

3. Also update the .yml file db cred as per yours

4. Run the application using Docker:
docker-compose up --build

This command builds the Docker images and starts the containers.

5. To check the status of the running containers, use:
docker-compose ps


## Manual Database Migrations

If the database tables are not migrated automatically, you can perform manual migrations using the following steps:

1. Access the web container's bash:

docker-compose exec web bash


2. Inside the container, run the Django migrations:

python manage.py makemigrations
python manage.py migrate


3. To exit the container, type `exit`.

## Architectural Overview

The application is structured around the Django framework, utilizing its robust features for authentication, data management, and RESTful API services. It integrates external services like Twilio for OTP-based authentication and Stripe for payment processing.

The system is containerized with Docker, ensuring consistency across different deployment environments and simplifying the deployment process.

## Additional Information

- It is recommended to have Docker Desktop installed if you are working on Windows or Mac.
- Ensure your Docker environment has enough resources allocated (CPUs, Memory, and Disk Space).
- For detailed logs during the application startup or debugging, use `docker-compose logs -f`.

## Contributions

Contributions are welcome! If you'd like to contribute, please fork the repository and use a feature branch. Pull requests are warmly welcome.


