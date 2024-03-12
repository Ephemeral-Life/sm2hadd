package main

import (
	"context"
	"github.com/Ephemeral-Life/sm2hadd/pb" // 替换为实际生成的protobuf包的路径
	"google.golang.org/grpc"
	"log"
	"net"
)

type server struct {
	pb.UnimplementedSM2CryptoServiceServer
}

func (s *server) GenerateKeyPair(ctx context.Context, in *pb.Empty) (*pb.KeyPair, error) {
	// 这里应调用之前定义的生成密钥对的函数，下同
	return &pb.KeyPair{}, nil
}

func (s *server) Encrypt(ctx context.Context, req *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	// 加密逻辑
	return &pb.EncryptResponse{}, nil
}

func (s *server) Decrypt(ctx context.Context, req *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	// 解密逻辑
	return &pb.DecryptResponse{}, nil
}

func (s *server) HomomorphicAdd(ctx context.Context, req *pb.HomomorphicAddRequest) (*pb.HomomorphicAddResponse, error) {
	// 同态加法逻辑
	return &pb.HomomorphicAddResponse{}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterSM2CryptoServiceServer(s, &server{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
