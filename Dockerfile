FROM python:3.9-slim

RUN apt-get update --fix-missing && apt-get install -y libpq-dev gcc postgresql-client

WORKDIR /app

COPY . /app

RUN pip install --trusted-host pypi.python.org -r requirements.txt

COPY wait-for-postgres.sh /usr/wait-for-postgres.sh
RUN chmod +x /usr/wait-for-postgres.sh

EXPOSE 8000

ENV NAME donatex

CMD ["/bin/bash", "-c", "/usr/wait-for-postgres.sh db && python manage.py makemigrations && python manage.py migrate && python manage.py runserver 0.0.0.0:8000"]

