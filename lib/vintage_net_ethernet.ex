defmodule VintageNetEthernet do
  @moduledoc """
  Support for common wired Ethernet interface configurations

  Configurations for this technology are maps with a `:type` field set to
  `VintageNetEthernet`. The following additional fields are supported:

  * `:ipv4` - IPv4 options. See VintageNet.IP.IPv4Config.
  * `:dhcpd` - DHCP daemon options if running a static IP configuration. See
    VintageNet.IP.DhcpdConfig.
  * `:mac_address` - A MAC address string or an MFArgs tuple. VintageNet will
    set the MAC address of the network interface to the value specified. If an
    MFArgs tuple is passed, VintageNet will `apply` it and use the return value
    as the address.

  An example DHCP configuration is:

  ```elixir
  %{type: VintageNetEthernet, ipv4: %{method: :dhcp}}
  ```

  An example static IP configuration is:

  ```elixir
  %{
    type: VintageNetEthernet,
    ipv4: %{
      method: :static,
      address: {192, 168, 0, 5},
      prefix_length: 24,
      gateway: {192, 168, 0, 1}
    }
  }
  ```
  """
  @behaviour VintageNet.Technology

  alias VintageNet.Interface.RawConfig
  alias VintageNet.IP.{DhcpdConfig, IPv4Config}
  alias VintageNetEthernet.Cookbook
  alias VintageNetEthernet.MacAddress
  alias VintageNetSupplicant.WPASupplicant

  require Logger

  @impl VintageNet.Technology
  def normalize(%{type: __MODULE__} = config) do
    config
    |> normalize_ethernet()
    |> normalize_mac_address()
    |> IPv4Config.normalize()
    |> DhcpdConfig.normalize()
  end

  defp normalize_ethernet(%{vintage_net_ethernet: %{wpa_supplicant_conf: conf}} = config) do
    %{config | vintage_net_ethernet: %{wpa_supplicant_conf: conf}}
  end

  defp normalize_ethernet(config) do
    config
  end

  defp normalize_mac_address(%{mac_address: mac_address} = config) do
    if MacAddress.valid?(mac_address) or mfargs?(mac_address) do
      config
    else
      raise ArgumentError, "Invalid MAC address #{inspect(mac_address)}"
    end
  end

  defp normalize_mac_address(config), do: config

  defp mfargs?({m, f, a}) when is_atom(m) and is_atom(f) and is_list(a), do: true
  defp mfargs?(_), do: false

  @impl VintageNet.Technology
  def to_raw_config(ifname, %{type: __MODULE__} = config, opts) do
    tmpdir = Keyword.fetch!(opts, :tmpdir)

    wpa_supplicant_conf_path = Path.join(tmpdir, "wpa_supplicant.conf.#{ifname}")
    control_interface_dir = Path.join(tmpdir, "wpa_supplicant")
    # control_interface_paths = ctrl_interface_paths(ifname, control_interface_dir, config)
    verbose = Map.get(config, :verbose, false)

    normalized_config = normalize(config)

    files = [
      {wpa_supplicant_conf_path,
       ethernet_to_supplicant_contents(
         normalized_config.vintage_net_ethernet,
         control_interface_dir
       )}
    ]

    wpa_supplicant_options = [
      wpa_supplicant: "wpa_supplicant",
      ifname: ifname,
      driver: "wired",
      wpa_supplicant_conf_path: wpa_supplicant_conf_path,
      control_path: control_interface_dir,
      verbose: verbose
    ]

    %RawConfig{
      ifname: ifname,
      type: __MODULE__,
      source_config: normalized_config,
      required_ifnames: [ifname],
      files: files,
      cleanup_files: [],
      restart_strategy: :rest_for_one,
      up_cmds: [],
      down_cmds: [],
      child_specs: [
        {WPASupplicant, wpa_supplicant_options}
      ]
    }
    |> add_mac_address_config(normalized_config)
    |> IPv4Config.add_config(normalized_config, opts)
    |> DhcpdConfig.add_config(normalized_config, opts)
  end

  defp ethernet_to_supplicant_contents(
         %{wpa_supplicant_conf: conf},
         control_interface_dir
       ) do
    [into_newlines(["ctrl_interface=#{control_interface_dir}"]), conf]
    |> IO.chardata_to_string()
  end

  defp ethernet_to_supplicant_contents(ethernet, control_interface_dir) do
    config = [
      "ctrl_interface=#{control_interface_dir}"
    ]

    iodata = [into_newlines(config), into_ethernet_network_config(ethernet)]
    IO.chardata_to_string(iodata)
  end

  defp into_ethernet_network_config(ethernet) do
    key_mgmt =
      if Map.has_key?(ethernet, :allowed_key_mgmt), do: :allowed_key_mgmt, else: :key_mgmt

    network_config([
      # Common settings
      into_config_string(ethernet, :ssid),
      into_config_string(ethernet, :bssid),
      into_config_string(ethernet, key_mgmt),
      into_config_string(ethernet, :scan_ssid),
      into_config_string(ethernet, :priority),
      into_config_string(ethernet, :bssid_allowlist),
      into_config_string(ethernet, :bssid_denylist),
      into_config_string(ethernet, :wps_disabled),
      into_config_string(ethernet, :mode),
      into_config_string(ethernet, :frequency),
      into_config_string(ethernet, :ieee80211w),

      # WPA-PSK settings
      into_config_string(ethernet, :psk),
      into_config_string(ethernet, :wpa_ptk_rekey),

      # MACSEC settings
      into_config_string(ethernet, :macsec_policy),
      into_config_string(ethernet, :macsec_integ_only),
      into_config_string(ethernet, :macsec_replay_protect),
      into_config_string(ethernet, :macsec_replay_window),
      into_config_string(ethernet, :macsec_port),
      into_config_string(ethernet, :mka_cak),
      into_config_string(ethernet, :mka_ckn),
      into_config_string(ethernet, :mka_priority),

      # EAP settings
      into_config_string(ethernet, :identity),
      into_config_string(ethernet, :anonymous_identity),
      into_config_string(ethernet, :password),
      into_config_string(ethernet, :pairwise),
      into_config_string(ethernet, :group),
      into_config_string(ethernet, :group_mgmt),
      into_config_string(ethernet, :eap),
      into_config_string(ethernet, :eapol_flags),
      into_config_string(ethernet, :phase1),
      into_config_string(ethernet, :phase2),
      into_config_string(ethernet, :fragment_size),
      into_config_string(ethernet, :ocsp),
      into_config_string(ethernet, :openssl_ciphers),
      into_config_string(ethernet, :erp),

      # SAE settings
      into_config_string(ethernet, :sae_password),

      # TODO:
      # These parts are files.
      # They should probably be added to the `files` part
      # of raw_config
      into_config_string(ethernet, :ca_cert),
      into_config_string(ethernet, :ca_cert2),
      into_config_string(ethernet, :dh_file),
      into_config_string(ethernet, :dh_file2),
      into_config_string(ethernet, :client_cert),
      into_config_string(ethernet, :client_cert2),
      into_config_string(ethernet, :private_key),
      into_config_string(ethernet, :private_key2),
      into_config_string(ethernet, :private_key_passwd),
      into_config_string(ethernet, :private_key2_passwd),
      into_config_string(ethernet, :pac_file),

      # WEP Settings
      into_config_string(ethernet, :auth_alg),
      into_config_string(ethernet, :wep_key0),
      into_config_string(ethernet, :wep_key1),
      into_config_string(ethernet, :wep_key2),
      into_config_string(ethernet, :wep_key3),
      into_config_string(ethernet, :wep_tx_keyidx),

      # SIM Settings
      into_config_string(ethernet, :pin),
      into_config_string(ethernet, :pcsc)
    ])
  end

  defp into_config_string(ethernet, opt_key) do
    case Map.get(ethernet, opt_key) do
      nil -> nil
      opt -> ethernet_opt_to_config_string(ethernet, opt_key, opt)
    end
  end

  defp into_config_string(ethernet, opt_key) do
    case Map.get(ethernet, opt_key) do
      nil -> nil
      opt -> ethernet_opt_to_config_string(ethernet, opt_key, opt)
    end
  end

  defp ethernet_opt_to_config_string(_ethernet, :ssid, ssid) do
    process_ssid = ssid |> escape_string |> do_wpa_supplicant_ssid_hack()
    "ssid=#{process_ssid}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :bssid, bssid) do
    "bssid=#{bssid}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :psk, psk) do
    "psk=#{psk}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :wpa_ptk_rekey, wpa_ptk_rekey) do
    "wpa_ptk_rekey=#{wpa_ptk_rekey}"
  end

  defp ethernet_opt_to_config_string(_ethernet, key_mgmt_key, key_mgmt)
       when key_mgmt_key in [:key_mgmt, :allowed_key_mgmt] do
    "key_mgmt=#{key_mgmt_to_string(key_mgmt)}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :mode, mode) do
    "mode=#{mode_to_string(mode)}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :ap_scan, value) do
    "ap_scan=#{value}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :scan_ssid, value) do
    "scan_ssid=#{value}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :priority, value) do
    "priority=#{value}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :frequency, value) do
    "frequency=#{value}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :identity, value) do
    "identity=#{escape_string(value)}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :anonymous_identity, value) do
    "anonymous_identity=#{escape_string(value)}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :password, value) do
    "password=#{escape_string(value)}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :phase1, value) do
    "phase1=#{escape_string(value)}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :phase2, value) do
    "phase2=#{escape_string(value)}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :pairwise, value) do
    "pairwise=#{value}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :group, value) do
    "group=#{value}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :eap, value) do
    "eap=#{value}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :eapol_flags, value) do
    "eapol_flags=#{value}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :ca_cert, value) do
    "ca_cert=#{escape_string(value)}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :ca_cert2, value) do
    "ca_cert2=#{escape_string(value)}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :client_cert, value) do
    "client_cert=#{escape_string(value)}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :client_cert2, value) do
    "client_cert2=#{escape_string(value)}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :private_key, value) do
    "private_key=#{escape_string(value)}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :private_key2, value) do
    "private_key2=#{escape_string(value)}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :private_key_passwd, value) do
    "private_key_passwd=#{escape_string(value)}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :private_key2_passwd, value) do
    "private_key2_passwd=#{escape_string(value)}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :pin, value) do
    "pin=#{inspect(value)}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :wep_tx_keyidx, value) do
    "wep_tx_keyidx=#{value}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :wep_key0, value) do
    "wep_key0=#{value}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :wep_key1, value) do
    "wep_key1=#{value}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :wep_key2, value) do
    "wep_key2=#{value}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :wep_key3, value) do
    "wep_key3=#{value}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :pcsc, value) do
    "pcsc=#{inspect(value)}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :bssid_denylist, value) do
    "bssid_blacklist=#{value}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :bssid_allowlist, value) do
    "bssid_whitelist=#{value}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :bgscan, value) do
    "bgscan=#{bgscan_to_string(value)}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :passive_scan, value) do
    "passive_scan=#{value}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :user_mpm, value) do
    "user_mpm=#{value}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :sae_password, value) do
    "sae_password=\"#{value}\""
  end

  defp ethernet_opt_to_config_string(_ethernet, :ieee80211w, value) do
    "ieee80211w=#{pmk_to_string(value)}"
  end

  defp ethernet_opt_to_config_string(_ethernet, :wps_cred_processing, value) do
    "wps_cred_processing=#{value}"
  end

  defp network_config(config) do
    ["network={", "\n", into_newlines(config), "}", "\n"]
  end

  defp escape_string(value) when is_binary(value) do
    # Use inspect since the Elixir API that escapes non-printable characters is
    # currently private.
    inspect(value, binaries: :as_strings)
  end

  defp into_newlines(config) do
    Enum.map(config, fn
      nil -> []
      conf -> [conf, "\n"]
    end)
  end

  defp do_wpa_supplicant_ssid_hack("\"" <> str) when byte_size(str) > 33 do
    # Work around wpa_supplicant complaining about SSIDs that are too
    # long when their unescaped length is greater than 32 characters
    Logger.warning("Trimming unusual SSID to avoid wpa_supplicant issue. Check config.")
    trimmed = binary_part(str, 0, 32) |> trim_orphan_backslash()
    "\"" <> trimmed <> "\""
  end

  defp do_wpa_supplicant_ssid_hack(str), do: str

  defp trim_orphan_backslash(<<s::30-bytes, second_last, ?\\>>) when second_last != ?\\ do
    <<s::binary, second_last>>
  end

  defp trim_orphan_backslash(s), do: s

  defp key_mgmt_to_string(key_mgmt) do
    key_mgmt |> List.wrap() |> Enum.map_join(" ", &key_mgmt_item_to_string/1)
  end

  defp key_mgmt_item_to_string(:none), do: "NONE"
  defp key_mgmt_item_to_string(:wpa_psk), do: "WPA-PSK"
  defp key_mgmt_item_to_string(:wpa_psk_sha256), do: "WPA-PSK-SHA256"
  defp key_mgmt_item_to_string(:wpa_eap), do: "WPA-EAP"
  defp key_mgmt_item_to_string(:IEEE8021X), do: "IEEE8021X"
  defp key_mgmt_item_to_string(:sae), do: "SAE"

  defp mode_to_string(:infrastructure), do: "0"
  defp mode_to_string(:ibss), do: "1"
  defp mode_to_string(:ap), do: "2"
  defp mode_to_string(:p2p_go), do: "3"
  defp mode_to_string(:p2p_group_formation), do: "4"
  defp mode_to_string(:mesh), do: "5"

  defp bgscan_to_string(:simple), do: "\"simple\""
  defp bgscan_to_string({:simple, args}), do: "\"simple:#{args}\""
  defp bgscan_to_string(:learn), do: "\"learn\""
  defp bgscan_to_string({:learn, args}), do: "\"learn:#{args}\""

  defp pmk_to_string(n) when n in [0, 1, 2], do: Integer.to_string(n)
  defp pmk_to_string(:disabled), do: "0"
  defp pmk_to_string(:optional), do: "1"
  defp pmk_to_string(:required), do: "2"

  defp add_mac_address_config(raw_config, %{mac_address: mac_address}) do
    resolved_mac = resolve_mac(mac_address)

    if MacAddress.valid?(resolved_mac) do
      new_up_cmds =
        raw_config.up_cmds ++
          [{:run, "ip", ["link", "set", raw_config.ifname, "address", resolved_mac]}]

      %{raw_config | up_cmds: new_up_cmds}
    else
      Logger.warning(
        "vintage_net_ethernet: ignoring invalid MAC address '#{inspect(resolved_mac)}'"
      )

      raw_config
    end
  end

  defp add_mac_address_config(raw_config, _config) do
    raw_config
  end

  defp resolve_mac({m, f, args}) do
    apply(m, f, args)
  rescue
    e -> {:error, e}
  end

  defp resolve_mac(mac_address), do: mac_address

  @impl VintageNet.Technology
  def ioctl(_ifname, _command, _args) do
    {:error, :unsupported}
  end

  @impl VintageNet.Technology
  def check_system(_opts) do
    # TODO
    :ok
  end

  @spec quick_configure(VintageNet.ifname()) :: :ok | {:error, term()}
  def quick_configure(ifname \\ "eth0") do
    with {:ok, config} <- Cookbook.dynamic_ipv4() do
      VintageNet.configure(ifname, config)
    end
  end
end
