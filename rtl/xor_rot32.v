// Y = (A ^ B) <<< 7 : 32 XORs, the rotation is pure wiring
module xor_rot32 (input wire [31:0] a, input wire [31:0] b, output wire [31:0] y);
  wire [31:0] x = a ^ b;
  assign y = {x[24:0], x[31:25]};
endmodule
