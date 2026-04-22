FROM python:3.10-slim

WORKDIR /app

# No X11/Tkinter needed for terminal version
RUN pip install --no-cache-dir requests

COPY . .

CMD ["python", "main_cli.py"]