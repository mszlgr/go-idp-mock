FROM golang:1.19.1-alpine3.16 as builder

ADD ./main.go /
ADD ./go.sum /
ADD ./go.mod /
WORKDIR /
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

FROM scratch
COPY --from=builder /main /
EXPOSE 8080
CMD ["/main"]
