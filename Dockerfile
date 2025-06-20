FROM amd64/python:3.13-slim
WORKDIR /app/crisp-backend
COPY . .
RUN pip install --upgrade pip
RUN pip3 install -r requirements.txt
EXPOSE 9000
CMD ["python3", "main.py"]