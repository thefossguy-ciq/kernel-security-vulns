// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2024, 2025 - Greg Kroah-Hartman <gregkh@linuxfoundation.org>
//
// dyad.rs - command line testing for dyad
//
// Initial test cases taken from dyad bats shell script testing,
// others added as found and needed.
//
use assert_cmd::assert::OutputAssertExt;
use assert_cmd::cargo;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn can_run() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    cmd.assert()
        .failure()
        .stdout(predicate::str::contains("Error: At least one --sha1 value is required"));

    Ok(())
}

#[test]
fn invalid_git_id() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    cmd.arg("--sha1=5dce04fefe3e");
    cmd.assert().failure().stderr(predicate::str::contains(
        "Error: The provided git SHA1 '5dce04fefe3e' could not be found in the repository",
    ));

    Ok(())
}

#[test]
fn invalid_vulnerable_git_id() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    cmd.arg("--vulnerable=5dce04fefe3e").arg("--sha1=d9407ff11809");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Error: The provided vulnerable git SHA1 '5dce04fefe3e' could not be found in the repository"));

    Ok(())
}

#[test]
fn fixed_single_stable_branch() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id 2a8664583d4d3655cfe5d36cf03f56b11530b69b\n\
         4.19.179:cb1f69d53ac8a417fc42df013526b54735194c14:4.19.279:2a8664583d4d3655cfe5d36cf03f56b11530b69b\n";

    cmd.arg("--sha1=2a8664583d4d");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn fixed_multiple_stable_branch() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id 371a3bc79c11b707d7a1b7a2c938dc3cc042fffb\n\
         4.13:349d39dc57396e3e9f39170905ff8d626eea9e44:4.14.189:39e0651cac9c80865b2838f297f95ffc0f34a1d8\n\
         4.13:349d39dc57396e3e9f39170905ff8d626eea9e44:4.19.134:febe56f21371ba1e51e8586c3ddf8f54fc62fe61\n\
         4.13:349d39dc57396e3e9f39170905ff8d626eea9e44:5.4.53:d3b7bacd1115400b94482dfc7efffc175c29b831\n\
         4.13:349d39dc57396e3e9f39170905ff8d626eea9e44:5.7.8:9006b543384ab10902819364c1205f11a1458571\n\
         4.13:349d39dc57396e3e9f39170905ff8d626eea9e44:5.8:371a3bc79c11b707d7a1b7a2c938dc3cc042fffb\n";

    cmd.arg("--sha1=371a3bc79c11");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn fixed_only_mainline_branch() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id 94959c0e796e41128483588d133b9a7003b409f9\n\
         0:0:6.8:94959c0e796e41128483588d133b9a7003b409f9\n";

    cmd.arg("--sha1=94959c0e796e");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn vulnerable_fixed_in_stable_and_then_mainline() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id d9407ff11809c6812bb84fe7be9c1367d758e5c8\n\
         6.6.16:699f5416c33e515424982eacbe5a8567c5f64f04:6.6.16:bd8740928aacda3d9a4cbb77e2ca3a951f20ba6b\n\
         6.7:ffa55858330f267beec995fc4f68098c91311c64:6.7.4:46826a3844068c0d3919eb4a24c3ba7bf5d24449\n\
         6.7:ffa55858330f267beec995fc4f68098c91311c64:6.8:d9407ff11809c6812bb84fe7be9c1367d758e5c8\n";

    cmd.arg("--sha1=d9407ff11809");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn vulnerable_always_fixed_in_stable_and_then_mainline() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id c481016bb4f8a9c059c39ac06e7b65e233a61f6a\n\
         0:0:6.6.16:d821cbe902f47b93681a5324d6a771417caf2727\n\
         0:0:6.7.4:1673211a38012e731373177b3a820a257b7964d2\n\
         0:0:6.8:c481016bb4f8a9c059c39ac06e7b65e233a61f6a\n";

    cmd.arg("--sha1=c481016bb4f8");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn unfixed_stable_branches_1() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id 34ab17cc6c2c1ac93d7e5d53bb972df9a968f085\n\
         5.8:371a3bc79c11b707d7a1b7a2c938dc3cc042fffb:5.10.36:c24a20912eef00587416628149c438e885eb1304\n\
         5.8:371a3bc79c11b707d7a1b7a2c938dc3cc042fffb:5.11.20:876a5f33e5d961d879c5436987c09b3d9ef70379\n\
         5.8:371a3bc79c11b707d7a1b7a2c938dc3cc042fffb:5.12.3:6bf443acf6ca4f666d0e4225614ba9993a3aa1a9\n\
         5.8:371a3bc79c11b707d7a1b7a2c938dc3cc042fffb:5.13:34ab17cc6c2c1ac93d7e5d53bb972df9a968f085\n\
         4.14.189:39e0651cac9c80865b2838f297f95ffc0f34a1d8:0:0\n\
         4.19.134:febe56f21371ba1e51e8586c3ddf8f54fc62fe61:0:0\n\
         5.4.53:d3b7bacd1115400b94482dfc7efffc175c29b831:0:0\n\
         5.7.8:9006b543384ab10902819364c1205f11a1458571:0:0\n";

    cmd.arg("--sha1=34ab17cc6c2c1a");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn unfixed_stable_branches_2() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id d375b98e0248980681e5e56b712026174d617198\n\
         4.10:fbfa743a9d2a0ffa24251764f10afc13eb21e739:4.19.306:135414f300c5db995e2a2f3bf0f455de9d014aee\n\
         4.10:fbfa743a9d2a0ffa24251764f10afc13eb21e739:5.4.268:3f15ba3dc14e6ee002ea01b4faddc3d49200377c\n\
         4.10:fbfa743a9d2a0ffa24251764f10afc13eb21e739:5.10.209:da23bd709b46168f7dfc36055801011222b076cd\n\
         4.10:fbfa743a9d2a0ffa24251764f10afc13eb21e739:5.15.148:4329426cf6b8e22b798db2331c7ef1dd2a9c748d\n\
         4.10:fbfa743a9d2a0ffa24251764f10afc13eb21e739:6.1.75:62a1fedeb14c7ac0947ef33fadbabd35ed2400a2\n\
         4.10:fbfa743a9d2a0ffa24251764f10afc13eb21e739:6.6.14:687c5d52fe53e602e76826dbd4d7af412747e183\n\
         4.10:fbfa743a9d2a0ffa24251764f10afc13eb21e739:6.7.2:ba8d904c274268b18ef3dc11d3ca7b24a96cb087\n\
         4.10:fbfa743a9d2a0ffa24251764f10afc13eb21e739:6.8:d375b98e0248980681e5e56b712026174d617198\n\
         3.2.87:a6f6bb6bc04a5f88a31f47a6123d3fbf5ee8d694:0:0\n\
         3.10.106:72bbf335e7aad09c88c50dbdd238f4faabd12174:0:0\n\
         3.12.71:decccc92ee0a978a1c268b5df16824cb6384ed3c:0:0\n\
         3.16.42:d3d9b59ab32160e3cc4edcf7e5fa7cecb53a7d25:0:0\n\
         3.18.49:d397f7035d2c754781bbe93b07b94d8cd898620c:0:0\n\
         4.4.50:41e07a7e01d951cfd4c9a7dac90c921269d89513:0:0\n\
         4.9.11:a7fe4e5d06338e1a82b1977eca37400951f99730:0:0\n";

    cmd.arg("--sha1=d375b98e024898");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn loads_of_fixes() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id fd94d9dadee58e09b49075240fe83423eb1dcd36\n\
         4.1:49499c3e6e18b7677a63316f3ff54a16533dc28f:4.19.316:28a97c43c9e32f437ebb8d6126f9bb7f3ca9521a\n\
         4.1:49499c3e6e18b7677a63316f3ff54a16533dc28f:5.4.279:cf39c4f77a773a547ac2bcf30ecdd303bb0c80cb\n\
         4.1:49499c3e6e18b7677a63316f3ff54a16533dc28f:5.10.198:a7d86a77c33ba1c357a7504341172cc1507f0698\n\
         4.1:49499c3e6e18b7677a63316f3ff54a16533dc28f:5.15.132:1ad7b189cc1411048434e8595ffcbe7873b71082\n\
         4.1:49499c3e6e18b7677a63316f3ff54a16533dc28f:6.1.54:d9ebfc0f21377690837ebbd119e679243e0099cc\n\
         4.1:49499c3e6e18b7677a63316f3ff54a16533dc28f:6.5.4:c8f292322ff16b9a2272a67de396c09a50e09dce\n\
         4.1:49499c3e6e18b7677a63316f3ff54a16533dc28f:6.6:fd94d9dadee58e09b49075240fe83423eb1dcd36\n";

    cmd.arg("--sha1=fd94d9dadee58e09b49075240fe83423eb1dcd36");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn no_fixes() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id df77fbd8c5b222c680444801ffd20e8bbc90a56e\n\
         0:0:5.4.189:0478ccdc8ea016de1ebaf6fe6da0275c2b258c5b\n\
         0:0:5.6.7:8e8542437bb4070423c9754d5ba270ffdbae8c8d\n\
         0:0:5.7:df77fbd8c5b222c680444801ffd20e8bbc90a56e\n";

    cmd.arg("--sha1=df77fbd8c5b222c680444801ffd20e8bbc90a56e");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn multiple_fixes_hard() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id 5578de4834fe0f2a34fedc7374be691443396d1f\n\
         2.6.19:446fda4f26822b2d42ab3396aafcedf38a9ff2b6:3.16.66:97bc3683c24999ee621d847c9348c75d2fe86272\n\
         2.6.19:446fda4f26822b2d42ab3396aafcedf38a9ff2b6:3.18.137:c61d01faa5550e06794dcf86125ccd325bfad950\n\
         2.6.19:446fda4f26822b2d42ab3396aafcedf38a9ff2b6:4.4.177:dc18101f95fa6e815f426316b8b9a5cee28a334e\n\
         2.6.19:446fda4f26822b2d42ab3396aafcedf38a9ff2b6:4.9.163:1c973f9c7cc2b3caae93192fdc8ecb3f0b4ac000\n\
         2.6.19:446fda4f26822b2d42ab3396aafcedf38a9ff2b6:4.14.106:fcfe700acdc1c72eab231300e82b962bac2b2b2c\n\
         2.6.19:446fda4f26822b2d42ab3396aafcedf38a9ff2b6:4.19.28:e3713abc4248aa6bcc11173d754c418b02a62cbb\n\
         2.6.19:446fda4f26822b2d42ab3396aafcedf38a9ff2b6:4.20.15:fbf9578919d6c91100ec63acf2cba641383f6c78\n\
         2.6.19:446fda4f26822b2d42ab3396aafcedf38a9ff2b6:5.0:5578de4834fe0f2a34fedc7374be691443396d1f\n";

    cmd.arg("--sha1=5578de4834fe0f2a34fedc7374be691443396d1f");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn lots_vuln_fix_in_same_version() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id 2ad5692db72874f02b9ad551d26345437ea4f7f3\n\
         4.4.268:a462067d7c8e6953a733bf5ade8db947b1bb5449:4.4.268:5871761c5f0f20d6e98bf3b6bd7486d857589554\n\
         4.9.268:145c89c441d27696961752bf51b323f347601bee:4.9.268:0c71d4c89559f72cec2592d078681a843bce570e\n\
         4.14.232:caf5ac93b3b5d5fac032fc11fbea680e115421b4:4.14.232:24b699bea7553fc0b98dad9d864befb6005ac7f1\n\
         4.19.187:92028d7a31e55d53e41cff679156b9432cffcb36:4.19.189:5c17cfe155d21954b4c7e2a78fa771cebcd86725\n\
         5.4.112:4a2933c88399c0ebc738db39bbce3ae89786d723:5.4.115:d7fad2ce15bdbbd0fec3ebe999fd7cab2267f53e\n\
         5.10.30:dc195928d7e4ec7b5cfc6cd10dc4c8d87a7c72ac:5.10.33:90642ee9eb581a13569b1c0bd57e85d962215273\n\
         5.11.14:388d05f70f1ee0cac4a2068fd295072f1a44152a:5.11.17:0f000005da31f6947f843ce6b3e3a960540c6e00\n\
         5.12:8a12f8836145ffe37e9c8733dce18c22fb668b66:5.12.1:41c44e1f3112d7265dae522c026399b2a42d19ef\n\
         5.12:8a12f8836145ffe37e9c8733dce18c22fb668b66:5.13:2ad5692db72874f02b9ad551d26345437ea4f7f3\n";

    cmd.arg("--sha1=2ad5692db72874f02b9ad551d26345437ea4f7f3");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn multiple_fixes_hard_to_pick_correct_pairs() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id aafe104aa9096827a429bc1358f8260ee565b7cc\n\
         2.6.30:14131f2f98ac350ee9e73faed916d2238a8b6a0d:4.4.269:91ca6f6a91f679c8645d7f3307e03ce86ad518c4\n\
         2.6.30:14131f2f98ac350ee9e73faed916d2238a8b6a0d:4.9.269:859b47a43f5a0e5b9a92b621dc6ceaad39fb5c8b\n\
         2.6.30:14131f2f98ac350ee9e73faed916d2238a8b6a0d:4.14.233:1fca00920327be96f3318224f502e4d5460f9545\n\
         2.6.30:14131f2f98ac350ee9e73faed916d2238a8b6a0d:4.19.191:d43d56dbf452ccecc1ec735cd4b6840118005d7c\n\
         2.6.30:14131f2f98ac350ee9e73faed916d2238a8b6a0d:5.4.118:c64da3294a7d59a4bf6874c664c13be892f15f44\n\
         2.6.30:14131f2f98ac350ee9e73faed916d2238a8b6a0d:5.10.36:a33614d52e97fc8077eb0b292189ca7d964cc534\n\
         2.6.30:14131f2f98ac350ee9e73faed916d2238a8b6a0d:5.11.20:6e2418576228eeb12e7ba82edb8f9500623942ff\n\
         2.6.30:14131f2f98ac350ee9e73faed916d2238a8b6a0d:5.12.3:2a1bd74b8186d7938bf004f5603f25b84785f63e\n\
         2.6.30:14131f2f98ac350ee9e73faed916d2238a8b6a0d:5.13:aafe104aa9096827a429bc1358f8260ee565b7cc\n";

    cmd.arg("--sha1=aafe104aa909");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn fake_fixes() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id 46a9ea6681907a3be6b6b0d43776dccc62cad6cf\n\
         6.0:0495e337b7039191dfce6e03f5f830454b1fae6b:6.1.56:a5569bb187521432f509b69dda7d29f78b2d38b0\n\
         6.0:0495e337b7039191dfce6e03f5f830454b1fae6b:6.5.6:51988be187b041e5355245957b0b9751fa382e0d\n\
         6.0:0495e337b7039191dfce6e03f5f830454b1fae6b:6.6:46a9ea6681907a3be6b6b0d43776dccc62cad6cf\n\
         5.19.8:357321557920c805de2b14832002465c320eea4f:0:0\n";

    cmd.arg("--sha1=46a9ea6681907a3be6b6b0d43776dccc62cad6cf");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn invalid_data_in_fixes() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id a97709f563a078e259bf0861cd259aa60332890a\n\
         5.1:3f1f3234bc2db1c16b9818b9a15a5d58ad45251c:5.4.118:e7ea8e46e3b777be26aa855fe07778c415f24926\n\
         5.1:3f1f3234bc2db1c16b9818b9a15a5d58ad45251c:5.10.36:7be4db5c2b59fa77071c93ca4329876fb9777202\n\
         5.1:3f1f3234bc2db1c16b9818b9a15a5d58ad45251c:5.11.20:ea817ac1014c04f47885532b55f5d0898deadfba\n\
         5.1:3f1f3234bc2db1c16b9818b9a15a5d58ad45251c:5.12.3:3f72d3709f53af72835af7dc8b15ba61611a0e36\n\
         5.1:3f1f3234bc2db1c16b9818b9a15a5d58ad45251c:5.13:a97709f563a078e259bf0861cd259aa60332890a\n";

    cmd.arg("--sha1=a97709f563a0");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn lots_stable_branches_4_x_vulnerable() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id d6938c1c76c64f42363d0d1f051e1b4641c2ad40\n\
         4.10:8d8e20e2d7bba8c50e64e0eca1cb83956f468e49:4.19.306:614235859d46cae23af6120f48bca9c4250a5392\n\
         4.10:8d8e20e2d7bba8c50e64e0eca1cb83956f468e49:5.4.268:36b6db699c03f951979e591564ed7a16f86772f2\n\
         4.10:8d8e20e2d7bba8c50e64e0eca1cb83956f468e49:5.10.209:977c2cf5637afc2649d314b6532d9c0e9eab1d84\n\
         4.10:8d8e20e2d7bba8c50e64e0eca1cb83956f468e49:5.15.148:995d6099d8b14d838b65883ca5be0e29742a24a8\n\
         4.10:8d8e20e2d7bba8c50e64e0eca1cb83956f468e49:6.1.75:50ee63b800c6997d3a21619cb32018924d689263\n\
         4.10:8d8e20e2d7bba8c50e64e0eca1cb83956f468e49:6.6.14:b019406e5ad933676258af7f6b13ced24df78d56\n\
         4.10:8d8e20e2d7bba8c50e64e0eca1cb83956f468e49:6.7.2:c149cc7c88cadf956111bd85cd03c5c11618c0b7\n\
         4.10:8d8e20e2d7bba8c50e64e0eca1cb83956f468e49:6.8:d6938c1c76c64f42363d0d1f051e1b4641c2ad40\n";

    cmd.arg("--sha1=d6938c1c76c6");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn lots_stable_branches_3_x_vulnerable() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id c95f919567d6f1914f13350af61a1b044ac85014\n\
         3.6:c7aa12252f5142b9eee2f6e34ca8870a8e7e048c:4.14.336:83724831dab1df80d4b6e33986a1a8307a89ebf1\n\
         3.6:c7aa12252f5142b9eee2f6e34ca8870a8e7e048c:4.19.305:df02150025a3ac134a29c3a847b334f53d4b0c4a\n\
         3.6:c7aa12252f5142b9eee2f6e34ca8870a8e7e048c:5.4.267:65c6ef02ff26c2f1b113d6ea93ee21a95dfdb96b\n\
         3.6:c7aa12252f5142b9eee2f6e34ca8870a8e7e048c:5.10.208:6adeb15cb6add45ad4dd054e598081a20e207fa3\n\
         3.6:c7aa12252f5142b9eee2f6e34ca8870a8e7e048c:5.15.147:802af3c88ad1e5194bb1ff4f47aaabd9c94b83c6\n\
         3.6:c7aa12252f5142b9eee2f6e34ca8870a8e7e048c:6.1.72:a4b0a9b80a963c617227629890a706de459d462b\n\
         3.6:c7aa12252f5142b9eee2f6e34ca8870a8e7e048c:6.6.11:fb195df90544f4559eebf6a99f4531cfed1bfcb2\n\
         3.6:c7aa12252f5142b9eee2f6e34ca8870a8e7e048c:6.7:c95f919567d6f1914f13350af61a1b044ac85014\n";

    cmd.arg("--sha1=c95f919567d6");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn stable_branches_have_git_ids_for_wrong_commits() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id b9b34ddbe2076ade359cd5ce7537d5ed019e9807\n\
         4.14.113:ae03b6b1c880a03d4771257336dc3bca156dd51b:4.14.233:4d542ddb88fb2f39bf7f14caa2902f3e8d06f6ba\n\
         4.19.19:f92a819b4cbef8c9527d9797110544b2055a4b96:4.19.190:0e2dfdc74a7f4036127356d42ea59388f153f42c\n\
         5.0:979d63d50c0c0f7bc537bf821e056cc9fe5abd38:5.4.117:53e0db429b37a32b8fc706d0d90eb4583ad13848\n\
         5.0:979d63d50c0c0f7bc537bf821e056cc9fe5abd38:5.10.35:2cfa537674cd1051a3b8111536d77d0558f33d5d\n\
         5.0:979d63d50c0c0f7bc537bf821e056cc9fe5abd38:5.11.19:6eba92a4d4be8feb4dc33976abac544fa99d6ecc\n\
         5.0:979d63d50c0c0f7bc537bf821e056cc9fe5abd38:5.12.2:7cf64d8679ca1cb20cf57d6a88bfee79a0922a66\n\
         5.0:979d63d50c0c0f7bc537bf821e056cc9fe5abd38:5.13:b9b34ddbe2076ade359cd5ce7537d5ed019e9807\n\
         4.20.6:078da99d449f64ca04d459cdbdcce513b64173cd:0:0\n";

    cmd.arg("--sha1=b9b34ddbe207");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn old_vulnerablity_multiple_fixes_out_of_order() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id afd09b617db3786b6ef3dc43e28fe728cfea84df\n\
         2.6.19:ac27a0ec112a089f1a5102bc8dffc79c8c815571:5.10.43:01d349a481f0591230300a9171330136f9159bcd\n\
         2.6.19:ac27a0ec112a089f1a5102bc8dffc79c8c815571:5.12.10:1385b23396d511d5233b8b921ac3058b3f86a5e1\n\
         2.6.19:ac27a0ec112a089f1a5102bc8dffc79c8c815571:5.13:afd09b617db3786b6ef3dc43e28fe728cfea84df\n";

    cmd.arg("--sha1=afd09b617db3786b6ef3dc43e28fe728cfea84df");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn complex_beast_old_stable_unfixed_stable_vulnerability_backported(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id 38d75297745f04206db9c29bdd75557f0344c7cc\n\
         4.19.93:f4c36f1999745c2160422fe2f362deadbe3a136b:4.19.306:c0a529ab2af0bbe06dc278655d2ad67725ee04bc\n\
         5.4.8:ca7851d46de8a8d69022c4e5feed0820483b5f46:5.4.268:0d5685c13d5591965830ef648f7a78ec6e62b071\n\
         5.5:72139dfa2464e43957d330266994740bb7be2535:5.10.209:cbc15095d1ff2075a6a07cd7b783d4d5d5238118\n\
         5.5:72139dfa2464e43957d330266994740bb7be2535:5.15.148:b9bced8ca7b1ff334366c657d2d6bf944817f02e\n\
         5.5:72139dfa2464e43957d330266994740bb7be2535:6.1.75:06b854238ee54e3c90b37858718c04f55c9b67b1\n\
         5.5:72139dfa2464e43957d330266994740bb7be2535:6.6.14:1ee2762cf0fba7c9df55e2be1a5e4a383397b05c\n\
         5.5:72139dfa2464e43957d330266994740bb7be2535:6.7.2:90c6cada5006f0945631e598277766ab37d2b51b\n\
         5.5:72139dfa2464e43957d330266994740bb7be2535:6.8:38d75297745f04206db9c29bdd75557f0344c7cc\n\
         4.9.225:f76905ce52653e8a821963c35d9013cff19b1399:0:0\n\
         4.14.182:450caf1faa0d7bbbd1da93d3ee8c5edea7bc51a8:0:0\n";

    cmd.arg("--sha1=38d75297745f");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn vulnerable_and_fixed_same_branch() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id 97cba232549b9fe7e491fb60a69cf93075015f29\n\
         6.6.19:c3682b63c60fdef04fc503d36d08bb84ee9758ad:6.6.19:7211800091a9e2d49ad34f59d47321ca09ae30a7\n\
         6.7.7:c5d47e80f6aa072912d94ddabfc846e4ac2fc8cc:6.7.7:3f6730b2261c62f94460137a0dcbbb1577e5112b\n\
         6.8:59f1622a5f05d948a7c665a458a3dd76ba73015e:6.8:97cba232549b9fe7e491fb60a69cf93075015f29\n";

    cmd.arg("--sha1=97cba232549b");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn vulnerable_and_fixed_same_branch_some_not() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id 2ad5692db72874f02b9ad551d26345437ea4f7f3\n\
         4.4.268:a462067d7c8e6953a733bf5ade8db947b1bb5449:4.4.268:5871761c5f0f20d6e98bf3b6bd7486d857589554\n\
         4.9.268:145c89c441d27696961752bf51b323f347601bee:4.9.268:0c71d4c89559f72cec2592d078681a843bce570e\n\
         4.14.232:caf5ac93b3b5d5fac032fc11fbea680e115421b4:4.14.232:24b699bea7553fc0b98dad9d864befb6005ac7f1\n\
         4.19.187:92028d7a31e55d53e41cff679156b9432cffcb36:4.19.189:5c17cfe155d21954b4c7e2a78fa771cebcd86725\n\
         5.4.112:4a2933c88399c0ebc738db39bbce3ae89786d723:5.4.115:d7fad2ce15bdbbd0fec3ebe999fd7cab2267f53e\n\
         5.10.30:dc195928d7e4ec7b5cfc6cd10dc4c8d87a7c72ac:5.10.33:90642ee9eb581a13569b1c0bd57e85d962215273\n\
         5.11.14:388d05f70f1ee0cac4a2068fd295072f1a44152a:5.11.17:0f000005da31f6947f843ce6b3e3a960540c6e00\n\
         5.12:8a12f8836145ffe37e9c8733dce18c22fb668b66:5.12.1:41c44e1f3112d7265dae522c026399b2a42d19ef\n\
         5.12:8a12f8836145ffe37e9c8733dce18c22fb668b66:5.13:2ad5692db72874f02b9ad551d26345437ea4f7f3\n";

    cmd.arg("--sha1=2ad5692db7");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn fixes_line_corrupted() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id e41a49fadbc80b60b48d3c095d9e2ee7ef7c9a8e\n\
         5.7:89b83f282d8ba380cf2124f88106c57df49c538c:5.10.46:f6ed2357541612a13a5841b3af4dc32ed984a25f\n\
         5.7:89b83f282d8ba380cf2124f88106c57df49c538c:5.12.13:ce6e8bee7a3883e8008b30f5887dbb426aac6a35\n\
         5.7:89b83f282d8ba380cf2124f88106c57df49c538c:5.13:e41a49fadbc80b60b48d3c095d9e2ee7ef7c9a8e\n";

    cmd.arg("--sha1=e41a49fadbc8");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn fixes_line_is_not_real() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id 8ee1b439b1540ae543149b15a2a61b9dff937d91\n\
         0:0:5.4.278:002364b2d594a9afc0385c09e00994c510b1d089\n\
         0:0:5.10.219:fd4bcb991ebaf0d1813d81d9983cfa99f9ef5328\n\
         0:0:5.15.161:902f6d656441a511ac25c6cffce74496db10a078\n\
         0:0:6.1.93:2ebcaa0e5db9b6044bb487ae1cf41bc601761567\n\
         0:0:6.6.33:7eeef1e935d23db5265233d92395bd5c648a4021\n\
         0:0:6.9.4:4e99103f757cdf636c6ee860994a19a346a11785\n\
         0:0:6.10:8ee1b439b1540ae543149b15a2a61b9dff937d91\n";

    cmd.arg("--sha1=8ee1b439b154");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn fixes_line_sha_is_not_in_tree() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id 259043e3b730e0aa6408bff27af7edf7a5c9101c\n\
         0:0:6.11:259043e3b730e0aa6408bff27af7edf7a5c9101c\n";

    cmd.arg("--sha1=259043e3b730e0aa6408bff27af7edf7a5c9101c");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn fixes_line_goes_back_in_time_to_fix_things_not_there_bizarrely() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id 547713d502f7b4b8efccd409cff84d731a23853b\n\
         6.7:5329aa5101f73c451bcd48deaf3f296685849d9c:6.7.2:92be3095c6ca1cdc46237839c6087555be9160e3\n\
         6.7:5329aa5101f73c451bcd48deaf3f296685849d9c:6.8:547713d502f7b4b8efccd409cff84d731a23853b\n";

    cmd.arg("--sha1=547713d502f7");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn reverts_in_some_branches_so_do_not_count_them() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id c45beebfde34aa71afbc48b2c54cdda623515037\n\
         6.6:16aac5ad1fa94894b798dd522c5c3a6a0628d7f0:6.6.74:f0c0ac84de17c37e6e84da65fb920f91dada55ad\n\
         6.6:16aac5ad1fa94894b798dd522c5c3a6a0628d7f0:6.12.10:3c7c90274ae339e1ad443c9be1c67a20b80b9c76\n\
         6.6:16aac5ad1fa94894b798dd522c5c3a6a0628d7f0:6.13:c45beebfde34aa71afbc48b2c54cdda623515037\n";

    cmd.arg("--sha1=c45beebfde34aa71afbc48b2c54cdda623515037");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn revert_with_no_fixes() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id 7198bfc2017644c6b92d2ecef9b8b8e0363bb5fd\n\
         5.15.34:5142720dbe51befeb25f204f912ef1ad93fba343:5.15.34:3b14aa053181709d42319d4145855025c23ddd12\n\
         5.16.19:d42740aab3ea29578d11a042bb50ded12ad3aa8a:5.16.19:24781c1b691c60c42748c669973d567a90573337\n\
         5.17.2:c6399f6f2f84921feebbf985e3819b1ad851ebe5:5.17.2:9d73b40f979737029bac724c39648016da3f914c\n\
         5.18:6d35d04a9e18990040e87d2bbf72689252669d54:5.18:7198bfc2017644c6b92d2ecef9b8b8e0363bb5fd\n";

    cmd.arg("--sha1=7198bfc2017644c6b92d2ecef9b8b8e0363bb5fd");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn fixes_line_requires_manual_lookup() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id 40d442f969fb1e871da6fca73d3f8aef1f888558\n\
         5.15.159:ed53949cc92e28aaa3463d246942bda1fbb7f307:5.15.159:580bcd6bf24f9975f97d81d5ef1b64cca9240df9\n\
         6.1.91:1caceadfb50432dbf6d808796cb6c34ebb6d662c:6.1.91:064688d70c33bb5b49dde6e972b9379a8b045d8a\n\
         6.6.31:427281f9498ed614f9aabc80e46ec077c487da6d:6.6.31:7bcba557d5c37cd09ecd5abbe7d50deb86c36d3f\n\
         6.8.10:02f05ed44b71152d5e11d29be28aed91c0489b4e:6.8.10:d1f768214320852766a60a815a0be8f14fba0cc3\n\
         6.9:2e4edfa1e2bd821a317e7d006517dcf2f3fac68d:6.9:40d442f969fb1e871da6fca73d3f8aef1f888558\n";

    cmd.arg("--sha1=40d442f969fb1e871da6fca73d3f8aef1f888558");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn multiple_vulnerable() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id 0a4ed2d97cb6d044196cc3e726b6699222b41019\n\
         5.8:ef8d563f184e1112651f2cbde383d43e599334e8:5.10.219:a6e1f7744e9b84f86a629a76024bba8468aa153b\n\
         5.8:ef8d563f184e1112651f2cbde383d43e599334e8:5.15.161:b5bac43875aa27ec032dbbb86173baae6dce6182\n\
         5.8:ef8d563f184e1112651f2cbde383d43e599334e8:6.1.93:5d47d63883735718825ca2efc4fca6915469774f\n\
         5.8:ef8d563f184e1112651f2cbde383d43e599334e8:6.6.33:329edb7c9e3b6ca27e6ca67ab1cdda1740fb3a2b\n\
         5.8:ef8d563f184e1112651f2cbde383d43e599334e8:6.9.4:69136304fd144144a4828c7b7b149d0f80321ba4\n\
         5.8:ef8d563f184e1112651f2cbde383d43e599334e8:6.10:0a4ed2d97cb6d044196cc3e726b6699222b41019\n";

    cmd.arg("--sha1=0a4ed2d97cb6d044196cc3e726b6699222b41019");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn fixes_line_hard_to_parse() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id e76946110137703c16423baf6ee177b751a34b7e\n\
         6.11:68f83057b913467a999e1bf9e0da6a119668f769:6.12.16:e7c16028a424dd35be1064a68fa318be4359310f\n\
         6.11:68f83057b913467a999e1bf9e0da6a119668f769:6.13.4:835b69c868f53f959d4986bbecd561ba6f38e492\n\
         6.11:68f83057b913467a999e1bf9e0da6a119668f769:6.14:e76946110137703c16423baf6ee177b751a34b7e\n";

    cmd.arg("--sha1=e76946110137703c16423baf6ee177b751a34b7e");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn vulnerable_for_stable_only() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id 10d75984495f7fe62152c3b0dbfa3f0a6b739c9b\n\
         # 	Setting original vulnerable kernel to be kernel 4.19.246 and git id ef481b262bba4f454351eec43f024fec942c2d4c\n\
         4.19.246:ef481b262bba4f454351eec43f024fec942c2d4c:4.19.306:10d75984495f7fe62152c3b0dbfa3f0a6b739c9b\n";

    cmd.arg("--vulnerable=ef481b262bba4f454351eec43f024fec942c2d4c")
        .arg("--sha1=10d75984495f");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn vulnerable_for_mainline() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id 4ef9ad19e17676b9ef071309bc62020e2373705d\n\
         # 	Setting original vulnerable kernel to be kernel 5.18 and git id 1854bc6e2420472676c5c90d3d6b15f6cd640e40\n\
         5.18:1854bc6e2420472676c5c90d3d6b15f6cd640e40:6.1.81:87632bc9ecff5ded93433bc0fca428019bdd1cfe\n\
         5.18:1854bc6e2420472676c5c90d3d6b15f6cd640e40:6.6.46:6ea9aa8d97e6563676094cb35755884173269555\n\
         5.18:1854bc6e2420472676c5c90d3d6b15f6cd640e40:6.7.6:7432376c913381c5f24d373a87ff629bbde94b47\n\
         5.18:1854bc6e2420472676c5c90d3d6b15f6cd640e40:6.8:4ef9ad19e17676b9ef071309bc62020e2373705d\n";

    cmd.arg("--vulnerable=1854bc6e2420")
        .arg("--sha1=4ef9ad19e17676b9ef071309bc62020e2373705d");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn vulnerable_for_backported_commit() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id a6dd15981c03f2cdc9a351a278f09b5479d53d2e\n\
         # 	Setting original vulnerable kernel to be kernel 6.12 and git id bf58f03931fdcf7b3c45cb76ac13244477a60f44\n\
         4.19.323:58556dcbd5606a5daccaee73b2130bc16b48e025:4.19.324:ce8a00a00e36f61f5a1e47734332420b68784c43\n\
         5.4.285:43b4fa6e0e238c6e2662f4fb61d9f51c2785fb1d:5.4.286:8d7a28eca7553d35d4ce192fa1f390f2357df41b\n\
         5.10.229:234682910971732cd4da96fd95946e296e486b38:5.10.230:2ac7f253deada4d449559b65a1c1cd0a6f6f19b7\n\
         5.15.170:6032287747f874b52dc8b9d7490e2799736e035f:5.15.172:27fc29b5376998c126c85cf9b15d9dfc2afc9cbe\n\
         6.1.115:cd67af3c1762de4c2483ae4dbdd98f9ea8fa56e3:6.1.117:1a9f55ed5b512f510ccd21ad527d532e60550e80\n\
         6.6.59:975ede2a7bec52b5da1428829b3439667c8a234b:6.6.61:a613a392417532ca5aaf3deac6e3277aa7aaef2b\n\
         6.11.6:1d7175f9c57b1abf9ecfbdfd53ea760761f52ffe:6.11.8:b9d9881237afeb52eddd70077b7174bf17e2fa30\n\
         6.12:bf58f03931fdcf7b3c45cb76ac13244477a60f44:6.12:a6dd15981c03f2cdc9a351a278f09b5479d53d2e\n";

    cmd.arg("--vulnerable=bf58f03931fdcf7b3c45cb76ac13244477a60f44")
        .arg("--sha1=a6dd15981c03f2cdc9a351a278f09b5479d53d2e");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn vulnerable_for_multiple_ids() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id 81665adf25d28a00a986533f1d3a5df76b79cad9\n\
         # 	Setting original vulnerable kernel to be kernel 6.7 and git id 1e18ec3e9d46e4ad2b6507c3bfc7f59e2ab449a2\n\
         # 	Setting original vulnerable kernel to be kernel 6.1.130 and git id 3fa58a6fbd1e9e5682d09cdafb08fba004cb12ec\n\
         6.7:1e18ec3e9d46e4ad2b6507c3bfc7f59e2ab449a2:6.8.7:38407914d48273d7f8ab765b9243658afe1c3ab6\n\
         6.7:1e18ec3e9d46e4ad2b6507c3bfc7f59e2ab449a2:6.9:81665adf25d28a00a986533f1d3a5df76b79cad9\n\
         6.1.130:3fa58a6fbd1e9e5682d09cdafb08fba004cb12ec:0:0\n";

    cmd.arg("-v").arg("1e18ec3e9d46")
        .arg("-v").arg("3fa58a6fbd1e")
        .arg("--sha1=81665adf25d28a00a986533f1d3a5df76b79cad9");
    cmd.assert()
       .success()
       .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn vulnerable_for_short_id() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id 81665adf25d28a00a986533f1d3a5df76b79cad9\n\
         # 	Setting original vulnerable kernel to be kernel 6.7 and git id 1e18ec3e9d46e4ad2b6507c3bfc7f59e2ab449a2\n\
         6.7:1e18ec3e9d46e4ad2b6507c3bfc7f59e2ab449a2:6.8.7:38407914d48273d7f8ab765b9243658afe1c3ab6\n\
         6.7:1e18ec3e9d46e4ad2b6507c3bfc7f59e2ab449a2:6.9:81665adf25d28a00a986533f1d3a5df76b79cad9\n";

    cmd.arg("--vulnerable=1e18ec3e9d46")
        .arg("--sha1=81665adf25d28a00a986533f1d3a5df76b79cad9");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn multiple_fixes_same_stable_release() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id 8ea607330a39184f51737c6ae706db7fdca7628e\n\
         5.19:97e6d7dab1ca4648821c790a2b7913d6d5d549db:6.1.125:43f4df339a4d375bedcad29a61ae6f0ee7a048f8\n\
         5.19:97e6d7dab1ca4648821c790a2b7913d6d5d549db:6.6.59:48068ccaea957469f1adf78dfd2c1c9a7e18f0fe\n\
         5.19:97e6d7dab1ca4648821c790a2b7913d6d5d549db:6.11.6:54bc31682660810af1bed7ca7a19f182df8d3df8\n\
         5.19:97e6d7dab1ca4648821c790a2b7913d6d5d549db:6.12:8ea607330a39184f51737c6ae706db7fdca7628e\n\
         5.15.45:6099a6c8a749a5c8d5f8b4c4342022a92072a02b:0:0\n\
         5.17.13:bfe25df63048edd4ceaf78a2fc755d5e2befc978:0:0\n\
         5.18.2:717c39718dbc4f7ebcbb7b625fb11851cd9007fe:0:0\n\
         5.15.45:5d0bba8232bf22ce13747cbfc8f696318ff01a50:0:0\n\
         5.17.13:70674d11d14eeecad90be4b409a22b902112ba32:0:0\n\
         5.18.2:a08d942ecbf46e23a192093f6983cb1d779f4fa8:0:0\n";

    cmd.arg("--sha1=8ea607330a39184f51737c6ae706db7fdca7628e");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn sort_releases_properly() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id 22207fd5c80177b860279653d017474b2812af5e\n\
         0:0:6.1.132:2e13f88e01ae7e28a7e831bf5c2409c4748e0a60\n\
         0:0:6.6.24:e87e08c94c9541b4e18c4c13f2f605935f512605\n\
         0:0:6.7.12:af054a5fb24a144f99895afce9519d709891894c\n\
         0:0:6.8.3:22f665ecfd1225afa1309ace623157d12bb9bb0c\n\
         0:0:6.9:22207fd5c80177b860279653d017474b2812af5e\n";

    cmd.arg("--sha1=22207fd5c80177b860279653d017474b2812af5e");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn vulnerable_in_mainline_and_stable_same_branch() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id b628510397b5cafa1f5d3e848a28affd1c635302\n\
         6.11:449d0d84bcd8246b508d07995326d13c54488b8c:6.12.14:fee921e3c641f64185abee83f9a6e65f0b380682\n\
         6.11:449d0d84bcd8246b508d07995326d13c54488b8c:6.13.3:e03db7c1255ebabba5e1a447754faeb138de15a2\n\
         6.11:449d0d84bcd8246b508d07995326d13c54488b8c:6.14:b628510397b5cafa1f5d3e848a28affd1c635302\n";

    cmd.arg("--sha1=b628510397b5cafa1f5d3e848a28affd1c635302");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn invalid_fixes_in_db() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id 4e32c25b58b945f976435bbe51f39b32d714052e\n\
         6.9:07fd7c329839cf0b8c7766883d830a1a0d12d1dd:6.10.10:03e2a1209a83a380df34a72f7d6d1bc6c74132c7\n\
         6.9:07fd7c329839cf0b8c7766883d830a1a0d12d1dd:6.11:4e32c25b58b945f976435bbe51f39b32d714052e\n";

    cmd.arg("--sha1=4e32c25b58b945f976435bbe51f39b32d714052e");
    cmd.assert()
        .success()
        .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn multiple_fixed_multiple_vulnerable_ids() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id 258ea41c926b7b3a16d0d7aa210a1401c4a1601b\n\
         # 	getting vulnerable:fixed pairs for git id bf373d2919d98f3d1fe1b19a0304f72fe74386d9\n\
         # 	Setting original vulnerable kernel to be kernel 6.6 and git id adda6e82a7de7d6d478f6c8ef127f0ac51c510a1\n\
         # 	Setting original vulnerable kernel to be kernel 6.9 and git id b48415afe5fd7e6f5912d4c45720217b77d8e7ea\n\
         6.6:adda6e82a7de7d6d478f6c8ef127f0ac51c510a1:6.6.4:e27877990e54bfe4246dd850f7ec8646c999ce58\n\
         6.6:adda6e82a7de7d6d478f6c8ef127f0ac51c510a1:6.7:258ea41c926b7b3a16d0d7aa210a1401c4a1601b\n\
         6.9:b48415afe5fd7e6f5912d4c45720217b77d8e7ea:6.11.11:48d52d3168749e10c1c37cd4ceccd18625851741\n\
         6.9:b48415afe5fd7e6f5912d4c45720217b77d8e7ea:6.12.2:776f13ad1f88485206f1dca5ef138553106950e5\n\
         6.9:b48415afe5fd7e6f5912d4c45720217b77d8e7ea:6.13:bf373d2919d98f3d1fe1b19a0304f72fe74386d9\n";

    cmd.arg("--sha1=258ea41c926b7b3a16d0d7aa210a1401c4a1601b")
       .arg("--sha1=bf373d2919d98f3d1fe1b19a0304f72fe74386d9")
       .arg("-v").arg("adda6e82a7de7d6d478f6c8ef127f0ac51c510a1")
       .arg("-v").arg("b48415afe5fd7e6f5912d4c45720217b77d8e7ea");
    cmd.assert()
       .success()
       .stdout(predicate::str::ends_with(output));

    Ok(())
}

#[test]
fn single_fixed_multiple_vulnerable_sort_order() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    let output =
        "# 	getting vulnerable:fixed pairs for git id b16510a530d1e6ab9683f04f8fb34f2e0f538275\n\
         # 	Setting original vulnerable kernel to be kernel 6.10 and git id c6ab5c915da460c0397960af3c308386c3f3247b\n\
         # 	Setting original vulnerable kernel to be kernel 6.13 and git id d6793ff974e07e4eea151d1f0805e92d042825a1\n\
         # 	Setting original vulnerable kernel to be kernel 6.13 and git id b04163863caf599d4348a05af5a71cf5d42f11dc\n\
         6.6.70:55779f26eab9af12474a447001bd17070f055712:6.6.99:f02f0218be412cff1c844addf58e002071be298b\n\
         6.13:d6793ff974e07e4eea151d1f0805e92d042825a1:6.14.5:921b8167f10708e38080f84e195cdc68a7a561f1\n\
         6.10:c6ab5c915da460c0397960af3c308386c3f3247b:6.15:b16510a530d1e6ab9683f04f8fb34f2e0f538275\n\
         6.13:d6793ff974e07e4eea151d1f0805e92d042825a1:6.15:b16510a530d1e6ab9683f04f8fb34f2e0f538275\n\
         6.13:b04163863caf599d4348a05af5a71cf5d42f11dc:6.15:b16510a530d1e6ab9683f04f8fb34f2e0f538275\n";

    cmd.arg("--sha1=b16510a530d1e6ab9683f04f8fb34f2e0f538275")
       .arg("--vulnerable=c6ab5c915da460c0397960af3c308386c3f3247b")
       .arg("--vulnerable=d6793ff974e07e4eea151d1f0805e92d042825a1")
       .arg("--vulnerable=b04163863caf599d4348a05af5a71cf5d42f11dc");
    cmd.assert()
       .success()
       .stdout(predicate::str::ends_with(output));

    Ok(())
}

/// Test for CVE-2024-27005: revert-based fixes on stable branches
///
/// This tests the scenario where a stable branch is fixed by reverting the
/// backported introducing commit, rather than by backporting the mainline fix.
///
/// Mainline:
///   - af42269c3523 introduces the vulnerability
///   - de1bf25b6d77 fixes it (backported to 6.6.29 and 6.8.8)
///
/// On 6.1 branch (fixed via revert instead of backporting mainline fix):
///   - ee42bfc791aa (backport of af42269c3523) introduces the vulnerability at 6.1.55
///   - 19ec82b3cad1 (revert of ee42bfc791aa) fixes it at 6.1.81
///
/// On 5.15 branch (also fixed via revert):
///   - 9be2957f014d (backport of af42269c3523) introduces the vulnerability at 5.15.133
///   - fe549d8e9763 (revert of 9be2957f014d) fixes it at 5.15.151
#[test]
fn revert_based_fix_on_stable_branch() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    // The output should include:
    // 1. The 5.15 revert-based fix: 5.15.133 -> 5.15.151
    // 2. The 6.1 revert-based fix: 6.1.55 -> 6.1.81
    // 3. The normal backport fixes on 6.6 and 6.8
    // 4. The mainline fix at 6.9
    // 5. The unfixed 6.5.5 branch
    cmd.arg("--sha1=de1bf25b6d771abdb52d43546cf57ad775fb68a1");
    let output = cmd.output()?;

    assert!(output.status.success(), "dyad command should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Check that the 6.1 revert-based fix is detected
    assert!(
        stdout.contains("6.1.55:ee42bfc791aa3cd78e29046f26a09d189beb3efb:6.1.81:19ec82b3cad1abef2a929262b8c1528f4e0c192d"),
        "Should detect 6.1 revert-based fix: 6.1.55 (ee42bfc791aa) -> 6.1.81 (19ec82b3cad1)"
    );

    // Check that the 5.15 revert-based fix is detected
    assert!(
        stdout.contains("5.15.133:9be2957f014d91088db1eb5dd09d9a03d7184dce:5.15.151:fe549d8e976300d0dd75bd904eb216bed8b145e0"),
        "Should detect 5.15 revert-based fix: 5.15.133 (9be2957f014d) -> 5.15.151 (fe549d8e9763)"
    );

    // Check that normal backport fixes are still detected
    assert!(
        stdout.contains("6.6.29:d0d04efa2e367921654b5106cc5c05e3757c2b42"),
        "Should detect 6.6.29 backport fix"
    );

    assert!(
        stdout.contains("6.8.8:4c65507121ea8e0b47fae6d2049c8688390d46b6"),
        "Should detect 6.8.8 backport fix"
    );

    // Check that mainline fix is detected
    assert!(
        stdout.contains("6.9:de1bf25b6d771abdb52d43546cf57ad775fb68a1"),
        "Should detect mainline fix at 6.9"
    );

    // Check that unfixed 6.5.5 is detected
    assert!(
        stdout.contains("6.5.5:2f3a124696d43de3c837f87a9f767c56ee86cf2a:0:0"),
        "Should detect unfixed 6.5.5 branch"
    );

    Ok(())
}

/// Test for complex case with multiple vulnerable/fixed pairs on same stable branch,
/// cross-version fixes, and unfixed stable branches.
/// This SHA fixes c490a0b5a4f3 which requires fixes table translation.
#[test]
fn multiple_fixes_same_stable_branch() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(cargo::cargo_bin!("dyad"));

    cmd.arg("--sha1=9f6ad5d533d1c71e51bdd06a5712c4fbc8768dfa");
    let output = cmd.output()?;

    assert!(output.status.success(), "dyad command should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Check cross-version fixes (6.0 vulnerability fixed in 6.1, 6.2, 6.3)
    assert!(
        stdout.contains("6.0:c490a0b5a4f36da3918181a8acdc6991d967c5f3:6.1.18:4be26d553a3f1d4f54f25353d1496c562002126d"),
        "Should detect 6.0 -> 6.1.18 fix"
    );
    assert!(
        stdout.contains("6.0:c490a0b5a4f36da3918181a8acdc6991d967c5f3:6.2.5:258809bf22bf71d53247856f374f2b1d055f2fd4"),
        "Should detect 6.0 -> 6.2.5 fix"
    );
    assert!(
        stdout.contains("6.0:c490a0b5a4f36da3918181a8acdc6991d967c5f3:6.3:9f6ad5d533d1c71e51bdd06a5712c4fbc8768dfa"),
        "Should detect 6.0 -> 6.3 mainline fix"
    );

    // Check multiple fixes on same stable branch (4.19 has two pairs)
    assert!(
        stdout.contains("4.19.257:2035c770bfdbcc82bd52e05871a7c82db9529e0f:4.19.312:6bdf4e6dfb60cbb6121ccf027d97ed2ec97c0bcb"),
        "Should detect first 4.19 fix pair"
    );
    assert!(
        stdout.contains("4.19.312:a217715338fd48f72114725aa7a40e484a781ca7:4.19.312:832580af82ace363205039a8e7c4ef04552ccc1a"),
        "Should detect second 4.19 fix pair"
    );

    // Check unfixed stable branches
    assert!(
        stdout.contains("4.9.327:18e28817cb516b39de6281f6db9b0618b2cc7b42:0:0"),
        "Should detect unfixed 4.9.327 branch"
    );
    assert!(
        stdout.contains("4.14.292:adf0112d9b8acb03485624220b4934f69bf13369:0:0"),
        "Should detect unfixed 4.14.292 branch"
    );
    assert!(
        stdout.contains("5.19.6:9be7fa7ead18a48940df7b59d993bbc8b9055c15:0:0"),
        "Should detect unfixed 5.19.6 branch"
    );

    Ok(())
}
