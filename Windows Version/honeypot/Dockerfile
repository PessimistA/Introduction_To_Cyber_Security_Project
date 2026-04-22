FROM python:3.10-slim

WORKDIR /app

# This line installs the missing module inside the container
RUN pip install requests

COPY . .

CMD ["python", "-u", "core.py"]