// One PRESENT round: addRoundKey -> 16 S-boxes -> pLayer (pure wiring)
module present_round (input wire [63:0] state_in, input wire [63:0] round_key,
                      output wire [63:0] state_out);
  wire [63:0] ark = state_in ^ round_key;
  wire [63:0] sb;
  genvar i;
  generate
    for (i = 0; i < 16; i = i + 1) begin : g_sbox
      present_sbox u (.x(ark[4*i+3:4*i]), .y(sb[4*i+3:4*i]));
    end
    for (i = 0; i < 63; i = i + 1) begin : g_player
      assign state_out[(16*i) % 63] = sb[i];
    end
  endgenerate
  assign state_out[63] = sb[63];
endmodule
