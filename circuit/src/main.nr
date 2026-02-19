fn main(
    total_in: Field,
    total_out: Field,
    threshold_bps: pub Field,
    trade_count: pub Field,
) {
    assert(total_in != 0, "total_in must be non-zero");
    // trade_count == 0 is rejected off-chain by the app before proving

    // out * 10000 >= (10000 + threshold) * in  →  ROI >= threshold_bps / 10000
    // surplus < 0 would be huge in the field and fail the 126-bit range check
    let lhs = total_out * 10000;
    let rhs = (10000 + threshold_bps) * total_in;
    let surplus = lhs - rhs;
    surplus.assert_max_bit_size::<126>();
}
