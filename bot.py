# Eternity Guard Final Code

import discord
from discord.ext import commands, tasks
from discord import app_commands
import collections
import datetime
import time
import sqlite3
import re
import asyncio
import os
from dotenv import load_dotenv

# --- Bot Configuration ---
# Bu ID'yi kendi ses kanalınızın ID'si ile değiştirebilir veya 0 bırakarak devre dışı bırakabilirsiniz.
VOICE_CHANNEL_ID = 0
BOT_ACTIVITY_NAME = "ETERNİTY TEAM"   # Botun "Oynuyor" durumunda görünecek yazı

# --- Database Management ---
class DatabaseManager:
    def __init__(self, db_name):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.setup_tables()

    def setup_tables(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                guild_id INTEGER PRIMARY KEY,
                spam_message_count INTEGER DEFAULT 6, spam_time_window INTEGER DEFAULT 5,
                max_mentions INTEGER DEFAULT 7, log_channel_id INTEGER,
                allow_invites INTEGER DEFAULT 0, max_message_length INTEGER DEFAULT 1500,
                raid_join_limit INTEGER DEFAULT 10, raid_time_window INTEGER DEFAULT 60,
                repetitive_check_count INTEGER DEFAULT 5, repetitive_unique_limit INTEGER DEFAULT 2,
                vanity_url TEXT,
                anti_nuke_enabled INTEGER DEFAULT 1,
                raid_protection_enabled INTEGER DEFAULT 1,
                spam_protection_enabled INTEGER DEFAULT 1,
                mention_protection_enabled INTEGER DEFAULT 1,
                invite_protection_enabled INTEGER DEFAULT 1,
                caps_protection_enabled INTEGER DEFAULT 1,
                blacklist_enabled INTEGER DEFAULT 1,
                repetitive_spam_enabled INTEGER DEFAULT 1,
                character_limit_enabled INTEGER DEFAULT 1
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS whitelists (
                guild_id INTEGER, item_type TEXT, item_id INTEGER,
                PRIMARY KEY (guild_id, item_type, item_id)
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS blacklist (
                guild_id INTEGER, word TEXT,
                PRIMARY KEY (guild_id, word)
            )
        ''')

        # Geriye dönük uyumluluk için eksik sütunları ekle
        existing_columns = [i[1] for i in self.cursor.execute('PRAGMA table_info(settings)')]
        new_columns = {
            'anti_nuke_enabled': 'INTEGER DEFAULT 1', 'raid_protection_enabled': 'INTEGER DEFAULT 1',
            'spam_protection_enabled': 'INTEGER DEFAULT 1', 'mention_protection_enabled': 'INTEGER DEFAULT 1',
            'invite_protection_enabled': 'INTEGER DEFAULT 1', 'caps_protection_enabled': 'INTEGER DEFAULT 1',
            'blacklist_enabled': 'INTEGER DEFAULT 1', 'repetitive_spam_enabled': 'INTEGER DEFAULT 1',
            'character_limit_enabled': 'INTEGER DEFAULT 1', 'vanity_url': 'TEXT'
        }
        for col, col_type in new_columns.items():
            if col not in existing_columns:
                try:
                    self.cursor.execute(f"ALTER TABLE settings ADD COLUMN {col} {col_type}")
                except sqlite3.OperationalError:
                    pass # Sütun zaten varsa hata verebilir, yoksay

        self.conn.commit()


    def get_config(self, guild_id):
        self.cursor.execute("SELECT * FROM settings WHERE guild_id = ?", (guild_id,))
        config_data = self.cursor.fetchone()
        if not config_data:
            self.cursor.execute("INSERT INTO settings (guild_id) VALUES (?)", (guild_id,))
            self.conn.commit()
            return self.get_config(guild_id)

        keys = [desc[0] for desc in self.cursor.description]
        config_dict = dict(zip(keys, config_data))

        defaults = {
            'spam_message_count': 6, 'spam_time_window': 5, 'max_mentions': 7,
            'log_channel_id': None, 'allow_invites': 0, 'max_message_length': 1500,
            'raid_join_limit': 10, 'raid_time_window': 60, 'repetitive_check_count': 5,
            'repetitive_unique_limit': 2, 'vanity_url': None, 'anti_nuke_enabled': 1,
            'raid_protection_enabled': 1, 'spam_protection_enabled': 1, 'mention_protection_enabled': 1,
            'invite_protection_enabled': 1, 'caps_protection_enabled': 1, 'blacklist_enabled': 1,
            'repetitive_spam_enabled': 1, 'character_limit_enabled': 1
        }
        for key, default_val in defaults.items():
            config_dict.setdefault(key, default_val)
        return config_dict

    def set_config_value(self, guild_id, key, value):
        self.cursor.execute(f"UPDATE settings SET {key} = ? WHERE guild_id = ?", (value, guild_id))
        self.conn.commit()

    def get_whitelist(self, guild_id):
        self.cursor.execute("SELECT item_type, item_id FROM whitelists WHERE guild_id = ?", (guild_id,))
        return self.cursor.fetchall()

    def add_to_whitelist(self, guild_id, item_type, item_id):
        try:
            self.cursor.execute("INSERT INTO whitelists (guild_id, item_type, item_id) VALUES (?, ?, ?)", (guild_id, item_type, item_id))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def remove_from_whitelist(self, guild_id, item_type, item_id):
        self.cursor.execute("DELETE FROM whitelists WHERE guild_id = ? AND item_type = ? AND item_id = ?", (guild_id, item_type, item_id))
        self.conn.commit()
        return self.cursor.rowcount > 0

    def get_blacklist(self, guild_id):
        self.cursor.execute("SELECT word FROM blacklist WHERE guild_id = ?", (guild_id,))
        return [row[0] for row in self.cursor.fetchall()]

    def add_to_blacklist(self, guild_id, word):
        try:
            self.cursor.execute("INSERT INTO blacklist (guild_id, word) VALUES (?, ?)", (guild_id, word.lower()))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def remove_from_blacklist(self, guild_id, word):
        self.cursor.execute("DELETE FROM blacklist WHERE guild_id = ? AND word = ?", (guild_id, word.lower()))
        self.conn.commit()
        return self.cursor.rowcount > 0

# --- Bot Kurulumu ve Veri Yapıları ---
intents = discord.Intents.all()
bot = commands.Bot(command_prefix="!", intents=intents)
bot.remove_command('help')

# Render'da kalıcı disk, yerelde ise mevcut klasörü kullanacak şekilde veritabanı yolunu ayarla
DB_PATH = os.path.join(os.environ.get('RENDER_DISK_PATH', '.'), 'eternity_guard.db')
db = DatabaseManager(DB_PATH)

# Önbellekler ve veri saklama yapıları
configs_cache = {}
whitelists_cache = collections.defaultdict(lambda: {'roles': set(), 'channels': set()})
blacklist_cache = collections.defaultdict(set)
user_messages = collections.defaultdict(lambda: collections.defaultdict(list))
user_recent_messages = collections.defaultdict(lambda: collections.defaultdict(lambda: collections.deque(maxlen=5)))
user_violations = collections.defaultdict(lambda: collections.defaultdict(lambda: {'level': 0, 'last_offense': 0}))
member_joins = collections.defaultdict(list)
raid_mode_active = collections.defaultdict(lambda: {'active': False, 'time': 0, 'original_level': None})

def load_guild_data(guild_id):
    configs_cache[guild_id] = db.get_config(guild_id)
    whitelist_data = db.get_whitelist(guild_id)
    whitelists_cache[guild_id]['roles'] = {item_id for t, item_id in whitelist_data if t == 'role'}
    whitelists_cache[guild_id]['channels'] = {item_id for t, item_id in whitelist_data if t == 'channel'}
    blacklist_cache[guild_id] = set(db.get_blacklist(guild_id))
    check_count = configs_cache[guild_id].get('repetitive_check_count', 5)
    user_recent_messages[guild_id] = collections.defaultdict(lambda: collections.deque(maxlen=check_count))

# --- Bot Olayları (Events) ---
@bot.event
async def on_ready():
    print(f"Bot aktif: {bot.user}")
    for guild in bot.guilds:
        load_guild_data(guild.id)
    print(f"{len(bot.guilds)} sunucunun yapılandırması yüklendi.")
    if VOICE_CHANNEL_ID != 0:
        setup_presence_and_voice.start()
    else:
        await bot.change_presence(activity=discord.Game(name=BOT_ACTIVITY_NAME))
    raid_mode_checker.start()
    await bot.tree.sync()
    print("Slash komutları senkronize edildi.")

@bot.event
async def on_guild_join(guild):
    print(f"Yeni sunucuya katıldı: {guild.name}")
    load_guild_data(guild.id)

@bot.event
async def on_message(message):
    if not message.guild or message.author.bot or message.author.id == message.guild.owner_id or message.author.top_role.position >= message.guild.me.top_role.position:
        return

    guild_id = message.guild.id
    if guild_id not in configs_cache:
        load_guild_data(guild_id)

    config = configs_cache.get(guild_id)
    whitelist = whitelists_cache.get(guild_id)

    if message.channel.id in whitelist['channels'] or any(role.id in whitelist['roles'] for role in message.author.roles):
        return

    if config.get('character_limit_enabled') and await check_character_limit(message, config): return
    if config.get('blacklist_enabled') and await check_blacklist(message, config): return
    if config.get('mention_protection_enabled') and await check_mass_mention(message, config): return
    if config.get('repetitive_spam_enabled') and await check_repetitive_spam(message, config): return
    if config.get('invite_protection_enabled') and await check_invite_links(message, config): return
    if config.get('caps_protection_enabled') and await check_caps_lock(message, config): return
    if config.get('spam_protection_enabled') and await check_rate_limit(message, config): return

    await bot.process_commands(message)

# --- Anti-Nuke Sistemi ---
async def instant_ban_and_cleanup_nuker(guild: discord.Guild, user: discord.User, reason: str):
    if not user: return
    member = guild.get_member(user.id)
    if not member or member.id == guild.owner_id or member.top_role.position >= guild.me.top_role.position: return
    
    config = configs_cache.get(guild.id, {})
    if not config.get("anti_nuke_enabled"): return

    log_channel = bot.get_channel(config.get("log_channel_id", 0))
    
    try:
        await member.ban(reason=f"Anti-Nuke: {reason}")
        if log_channel:
            alert_embed = discord.Embed(
                title="🚨 ACİL DURUM: NUKE SALDIRISI DURDURULDU 🚨",
                color=0xff0000,
                timestamp=datetime.datetime.now(datetime.timezone.utc)
            )
            alert_embed.description = (
                f"**Kullanıcı:** {member.mention} (`{member.id}`)\n"
                f"**Şüpheli Eylem:** `{reason}`\n\n"
                f"Bu kullanıcı **anında ve otomatik olarak** sunucudan yasaklandı. Otomatik temizlik başlatılıyor..."
            )
            await log_channel.send(content=guild.owner.mention, embed=alert_embed)
        
        await asyncio.sleep(1) 
        channels_to_delete, roles_to_delete = [], []
        async for entry in guild.audit_logs(limit=100, after=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=20)):
            if entry.user and entry.user.id == member.id:
                if entry.action == discord.AuditLogAction.channel_create: channels_to_delete.append(entry.target)
                elif entry.action == discord.AuditLogAction.role_create: roles_to_delete.append(entry.target)
        
        deleted_channels_count = sum(1 for channel in channels_to_delete if await delete_target(channel, "Anti-Nuke Temizliği"))
        deleted_roles_count = sum(1 for role in roles_to_delete if await delete_target(role, "Anti-Nuke Temizliği"))
        
        if log_channel and (deleted_channels_count > 0 or deleted_roles_count > 0):
            await log_channel.send(f"✅ **Otomatik Temizlik Tamamlandı:** `{deleted_channels_count}` spam kanal ve `{deleted_roles_count}` spam rol silindi.")

    except discord.Forbidden:
        if log_channel:
            await log_channel.send(f"⚠️ **Hata:** {member.mention} yasaklanamadı. Botun 'Üyeleri Yasakla' iznini ve rol hiyerarşisini kontrol edin.")
    except Exception as e:
        if log_channel:
            await log_channel.send(f"⚠️ **Hata:** Nuke koruması/temizliği sırasında bir sorun oluştu: `{e}`")

async def delete_target(target, reason):
    try:
        await target.delete(reason=reason)
        return True
    except:
        return False

async def get_audit_log_user(guild, action):
    await asyncio.sleep(0.25)
    try:
        async for entry in guild.audit_logs(limit=1, action=action):
            return entry.user
    except:
        return None

# Anti-Nuke Olay Dinleyicileri
@bot.event
async def on_guild_channel_delete(channel): await instant_ban_and_cleanup_nuker(channel.guild, await get_audit_log_user(channel.guild, discord.AuditLogAction.channel_delete), f"'{channel.name}' kanalını sildi")
@bot.event
async def on_guild_channel_create(channel): await instant_ban_and_cleanup_nuker(channel.guild, await get_audit_log_user(channel.guild, discord.AuditLogAction.channel_create), f"'{channel.name}' kanalını oluşturdu")
@bot.event
async def on_member_ban(guild, user_banned): await instant_ban_and_cleanup_nuker(guild, await get_audit_log_user(guild, discord.AuditLogAction.ban), f"'{user_banned.name}' kullanıcısını yasakladı")
@bot.event
async def on_member_kick(guild, member): await instant_ban_and_cleanup_nuker(guild, await get_audit_log_user(guild, discord.AuditLogAction.kick), f"'{member.name}' kullanıcısını attı")
@bot.event
async def on_guild_role_create(role): await instant_ban_and_cleanup_nuker(role.guild, await get_audit_log_user(role.guild, discord.AuditLogAction.role_create), f"'{role.name}' rolünü oluşturdu")
@bot.event
async def on_guild_role_delete(role): await instant_ban_and_cleanup_nuker(role.guild, await get_audit_log_user(role.guild, discord.AuditLogAction.role_delete), f"'{role.name}' rolünü sildi")
@bot.event
async def on_member_update(before, after):
    if before.roles != after.roles:
        user = await get_audit_log_user(before.guild, discord.AuditLogAction.member_role_update)
        # Sadece tehlikeli yetkiler eklendiğinde tetiklen
        dangerous_perms = [
            discord.Permissions.administrator, discord.Permissions.ban_members,
            discord.Permissions.kick_members, discord.Permissions.manage_channels,
            discord.Permissions.manage_guild, discord.Permissions.manage_roles
        ]
        added_roles = set(after.roles) - set(before.roles)
        for role in added_roles:
            if any(p[1] for p in role.permissions if p[0] in [dp.name for dp in dangerous_perms]):
                await instant_ban_and_cleanup_nuker(before.guild, user, f"'{before.name}' kullanıcısına tehlikeli yetkiler verdi")
                break


@bot.event
async def on_guild_update(before: discord.Guild, after: discord.Guild):
    config = configs_cache.get(after.id, {})
    correct_vanity = config.get("vanity_url")
    if correct_vanity and before.vanity_url_code != after.vanity_url_code:
        log_channel = bot.get_channel(config.get("log_channel_id", 0))
        try:
            await after.edit(vanity_code=correct_vanity, reason="URL Koruma")
            if log_channel:
                changer = await get_audit_log_user(after, discord.AuditLogAction.guild_update)
                await log_channel.send(f"🚨 **URL Koruma:** Sunucu URL'si `{changer.mention if changer else 'Bilinmeyen'}` tarafından değiştirildi ve anında geri alındı!")
        except Exception as e:
            if log_channel:
                await log_channel.send(f"⚠️ **Hata:** Sunucu URL'si geri alınamadı! Başka bir sunucu tarafından alınmış olabilir. Hata: `{e}`")

# --- Spam Koruma ve Diğer Fonksiyonlar ---
async def check_character_limit(message, config):
    limit = config.get("max_message_length", 1500)
    if limit > 0 and len(message.content) > limit: return await handle_violation(message, "Karakter Limiti Aşıldı", config)
    return False
async def check_rate_limit(message, config): return await handle_simple_violation(message, "Hızlı Mesaj (Flood)", config, "rate_limit")
async def check_mass_mention(message, config):
    if len(message.mentions) > config["max_mentions"] or message.mention_everyone: return await handle_violation(message, "Toplu Etiketleme", config)
    return False
async def check_invite_links(message, config): return await handle_simple_violation(message, "Yetkisiz Davet Linki", config, "invite")
async def check_caps_lock(message, config): return await handle_simple_violation(message, "Aşırı Büyük Harf", config, "caps")
async def check_blacklist(message, config):
    if any(word in message.content.lower() for word in blacklist_cache[message.guild.id]): return await handle_violation(message, "Yasaklı Kelime", config)
    return False
async def check_repetitive_spam(message, config):
    user_id, guild_id = message.author.id, message.guild.id
    check_count, unique_limit = config.get('repetitive_check_count', 5), config.get('repetitive_unique_limit', 2)
    user_recent_messages[guild_id][user_id].append(message.content)
    if len(user_recent_messages[guild_id][user_id]) == check_count and len(set(user_recent_messages[guild_id][user_id])) <= unique_limit:
        return await handle_violation(message, "Tekrarlayan Spam", config, purge_limit=check_count)
    return False
async def handle_simple_violation(message, reason, config, violation_type):
    detected = False
    if violation_type == "rate_limit":
        user_id, guild_id, current_time = message.author.id, message.guild.id, time.time()
        time_window, msg_count = config["spam_time_window"], config["spam_message_count"]
        user_messages[guild_id][user_id] = [t for t in user_messages[guild_id][user_id] if current_time - t < time_window]
        user_messages[guild_id][user_id].append(current_time)
        if len(user_messages[guild_id][user_id]) > msg_count: detected = True
    elif violation_type == "invite" and not config["allow_invites"] and re.search(r"(discord\.gg/|discordapp\.com/invite/)", message.content): detected = True
    elif violation_type == "caps" and len(message.content) > 15 and sum(1 for c in message.content if c.isupper()) / len(message.content) > 0.7: detected = True
    if not detected: return False
    try: await message.delete()
    except: pass
    log_channel = bot.get_channel(config.get("log_channel_id", 0))
    if log_channel:
        embed = discord.Embed(title="Küçük İhlal (Sessiz)", color=discord.Color.gold(), timestamp=datetime.datetime.now(datetime.timezone.utc))
        embed.add_field(name="Kullanıcı", value=f"{message.author.mention}", inline=False).add_field(name="Eylem", value=f"Mesaj silindi. Sebep: `{reason}`.", inline=False)
        await log_channel.send(embed=embed)
    return True
async def handle_violation(message, reason, config, purge_limit=1):
    author, guild, channel = message.author, message.guild, message.channel
    user_id, guild_id = author.id, guild.id
    last_offense_time = user_violations[guild_id][user_id].get('last_offense', 0)
    if time.time() - last_offense_time > 3600: user_violations[guild_id][user_id]['level'] = 0
    user_violations[guild_id][user_id]['level'] += 1; user_violations[guild_id][user_id]['last_offense'] = time.time()
    level = user_violations[guild_id][user_id]['level']
    log_channel = bot.get_channel(config.get("log_channel_id", 0))
    try:
        if purge_limit > 1 and channel: await channel.purge(limit=purge_limit, check=lambda m: m.author.id == user_id, after=message.created_at - datetime.timedelta(seconds=10), oldest_first=False)
        elif purge_limit == 1 and message and message.channel: await message.delete()
    except: pass
    punishment_desc = ""
    if level == 1: punishment_desc = f"Uyarıldı. Sebep: `{reason}`."
    elif level == 2:
        duration = datetime.timedelta(minutes=5); punishment_desc = f"5 dakika susturuldu. Sebep: `{reason}`."
        try: await author.timeout(duration, reason=reason)
        except: punishment_desc += " (Yetersiz yetki)"
    elif level == 3:
        duration = datetime.timedelta(minutes=30); punishment_desc = f"30 dakika susturuldu. Sebep: `{reason}`."
        try: await author.timeout(duration, reason=reason)
        except: punishment_desc += " (Yetersiz yetki)"
    elif level == 4:
        punishment_desc = f"Sunucudan atıldı. Sebep: `{reason}`.";
        try: await author.kick(reason=reason)
        except: punishment_desc += " (Yetersiz yetki)"
    else:
        punishment_desc = f"Sunucudan yasaklandı. Sebep: `{reason}`.";
        try: await author.ban(reason=reason)
        except: punishment_desc += " (Yetersiz yetki)"
    if log_channel:
        embed = discord.Embed(title="BÜYÜK İHLAL", color=discord.Color.red(), timestamp=datetime.datetime.now(datetime.timezone.utc))
        embed.add_field(name="Kullanıcı", value=f"{author.mention} (`{author.id}`)", inline=False).add_field(name="Eylem", value=punishment_desc, inline=False).set_footer(text=f"Yeni İhlal Seviyesi: {level}")
        await log_channel.send(embed=embed)
    return True

# --- Arka Plan Görevleri ---
@tasks.loop(seconds=60)
async def setup_presence_and_voice():
    await bot.wait_until_ready()
    try:
        channel = bot.get_channel(VOICE_CHANNEL_ID)
        if isinstance(channel, discord.VoiceChannel):
            if not bot.voice_clients: vc = await channel.connect()
            else: vc = bot.voice_clients[0]; await vc.move_to(channel)
            await vc.guild.change_voice_state(channel=channel, self_deaf=True, self_mute=True)
    except Exception as e: 
        print(f"Ses kanalına bağlanırken hata: {e}")
        setup_presence_and_voice.stop() # Hata alınca döngüyü durdur

@tasks.loop(minutes=1)
async def raid_mode_checker():
    now = time.time()
    for guild_id, status in list(raid_mode_active.items()):
        if status['active'] and now - status['time'] > 900:
            guild = bot.get_guild(guild_id)
            config = configs_cache.get(guild_id, {})
            log_channel = bot.get_channel(config.get("log_channel_id", 0))
            if guild and status['original_level'] is not None:
                try:
                    await guild.edit(verification_level=status['original_level'], reason="Anti-Raid Modu Devre Dışı Bırakıldı")
                    raid_mode_active[guild_id] = {'active': False, 'time': 0, 'original_level': None}
                    if log_channel: await log_channel.send("✅ **Anti-Raid Modu Devre Dışı Bırakıldı.** Sunucu doğrulama seviyesi normale döndü.")
                except:
                    if log_channel: await log_channel.send("⚠️ **Hata:** Anti-Raid modu devre dışı bırakılamadı.")

# --- Slash Komutları ---
@bot.tree.command(name="eternity", description="Botun tüm koruma ve ayar komutlarını gösterir.")
@app_commands.checks.has_permissions(administrator=True)
async def eternity_help_command(interaction: discord.Interaction):
    embed = discord.Embed(title="Eternity Guard Botu Komutları", description="Sunucunuzu spam, raid ve nuke saldırılarına karşı korur.", color=discord.Color.purple())
    embed.add_field(name="⚙️ Genel Ayarlar (`/config`)", value="`show`: Tüm mevcut ayarları gösterir.\n`set <ayar> <değer>`: Bir ayarı değiştirir. Modülleri açıp kapatmak için de bu komut kullanılır (değer: `true`/`false`).", inline=False)
    embed.add_field(name="🛡️ Beyaz Liste (`/whitelist`)", value="`add-role <rol>`: Rolü denetimlerden muaf tutar.\n`remove-role <rol>`\n`add-channel <kanal>`: Kanalı denetimlerden muaf tutar.\n`remove-channel <kanal>`", inline=False)
    embed.add_field(name="🚫 Karaliste (`/blacklist`)", value="`add <kelime>`, `remove <kelime>`, `list`.", inline=False)
    embed.set_footer(text="Eternity Guard | ETERNİTY TEAM")
    await interaction.response.send_message(embed=embed, ephemeral=True)

config_group = app_commands.Group(name="config", description="Botun ayarlarını yönet.")
whitelist_group = app_commands.Group(name="whitelist", description="Denetimlerden muaf rolleri/kanalları yönet.")
blacklist_group = app_commands.Group(name="blacklist", description="Yasaklı kelimeleri yönet.")

@config_group.command(name="show", description="Mevcut sunucu ayarlarını gösterir.")
@app_commands.checks.has_permissions(administrator=True)
async def show_config(interaction: discord.Interaction):
    config = configs_cache[interaction.guild.id]
    embed = discord.Embed(title=f"{interaction.guild.name} Sunucu Ayarları", color=discord.Color.blue())
    for key, value in sorted(config.items()):
        if key == "log_channel_id" and value: value = f"<#{value}> ({value})"
        if "enabled" in key:
            status = "✅ Aktif" if value else "❌ Pasif"
            embed.add_field(name=key, value=f"`{status}`", inline=True)
        else:
            embed.add_field(name=key, value=f"`{value}`" if value is not None else "`Ayarlanmamış`", inline=True)
    await interaction.response.send_message(embed=embed, ephemeral=True)

@config_group.command(name="set", description="Bir ayarın değerini değiştirir. Modüller için true/false kullanın.")
@app_commands.checks.has_permissions(administrator=True)
async def set_config(interaction: discord.Interaction, setting: str, value: str):
    guild_id = interaction.guild.id
    config = configs_cache.get(guild_id)
    setting = setting.lower()
    if setting not in config:
        await interaction.response.send_message(f"Geçersiz ayar. Kullanılabilir ayarlar için `/config show` komutunu kullanın.", ephemeral=True)
        return
    
    try:
        current_type = type(config.get(setting))
        new_value = value
        
        if "enabled" in setting:
            if value.lower() in ['true', '1', 'on', 'aktif', 'acik']: new_value = 1
            elif value.lower() in ['false', '0', 'off', 'pasif', 'kapali']: new_value = 0
            else: raise ValueError("Geçersiz değer. 'true' veya 'false' kullanın.")
        elif setting == "log_channel_id":
            new_value = int(value.strip('<#>')) if value.isdigit() or (value.startswith('<#') and value.endswith('>')) else None
        elif setting == "vanity_url":
            new_value = value if value.lower() != 'none' else None
        elif current_type is int: new_value = int(value)
        elif current_type is float: new_value = float(value)
        
        db.set_config_value(guild_id, setting, new_value)
        load_guild_data(guild_id)
        await interaction.response.send_message(f"✅ Ayar `{setting}` başarıyla `{value}` olarak güncellendi.", ephemeral=True)
    except Exception as e:
        await interaction.response.send_message(f"Hata: Değer, ayar türüyle eşleşmiyor veya geçersiz. `{e}`", ephemeral=True)

@whitelist_group.command(name="add-role", description="Bir rolü beyaz listeye ekler (denetimlerden muaf tutar).")
@app_commands.checks.has_permissions(administrator=True)
async def add_whitelist_role(interaction: discord.Interaction, role: discord.Role):
    if db.add_to_whitelist(interaction.guild.id, 'role', role.id):
        load_guild_data(interaction.guild.id)
        await interaction.response.send_message(f"✅ {role.mention} rolü denetimlerden muaf tutuldu.", ephemeral=True)
    else:
        await interaction.response.send_message("Bu rol zaten beyaz listede.", ephemeral=True)

@whitelist_group.command(name="remove-role", description="Bir rolü beyaz listeden kaldırır.")
@app_commands.checks.has_permissions(administrator=True)
async def remove_whitelist_role(interaction: discord.Interaction, role: discord.Role):
    if db.remove_from_whitelist(interaction.guild.id, 'role', role.id):
        load_guild_data(interaction.guild.id)
        await interaction.response.send_message(f"🗑️ {role.mention} rolü artık denetlenecek.", ephemeral=True)
    else:
        await interaction.response.send_message("Bu rol beyaz listede değil.", ephemeral=True)

@whitelist_group.command(name="add-channel", description="Bir kanalı beyaz listeye ekler (denetimlerden muaf tutar).")
@app_commands.checks.has_permissions(administrator=True)
async def add_whitelist_channel(interaction: discord.Interaction, channel: discord.TextChannel):
    if db.add_to_whitelist(interaction.guild.id, 'channel', channel.id):
        load_guild_data(interaction.guild.id)
        await interaction.response.send_message(f"✅ {channel.mention} kanalı denetimlerden muaf tutuldu.", ephemeral=True)
    else:
        await interaction.response.send_message("Bu kanal zaten beyaz listede.", ephemeral=True)

@whitelist_group.command(name="remove-channel", description="Bir kanalı beyaz listeden kaldırır.")
@app_commands.checks.has_permissions(administrator=True)
async def remove_whitelist_channel(interaction: discord.Interaction, channel: discord.TextChannel):
    if db.remove_from_whitelist(interaction.guild.id, 'channel', channel.id):
        load_guild_data(interaction.guild.id)
        await interaction.response.send_message(f"🗑️ {channel.mention} kanalı artık denetlenecek.", ephemeral=True)
    else:
        await interaction.response.send_message("Bu kanal beyaz listede değil.", ephemeral=True)

@blacklist_group.command(name="add", description="Yasaklı kelime listesine bir kelime ekler.")
@app_commands.checks.has_permissions(administrator=True)
async def add_blacklist(interaction: discord.Interaction, word: str):
    if db.add_to_blacklist(interaction.guild.id, word):
        load_guild_data(interaction.guild.id)
        await interaction.response.send_message(f"✅ `{word}` kelimesi karalisteye eklendi.", ephemeral=True)
    else:
        await interaction.response.send_message("Bu kelime zaten karalistede.", ephemeral=True)

@blacklist_group.command(name="remove", description="Bir kelimeyi yasaklı kelime listesinden kaldırır.")
@app_commands.checks.has_permissions(administrator=True)
async def remove_blacklist(interaction: discord.Interaction, word: str):
    if db.remove_from_blacklist(interaction.guild.id, word):
        load_guild_data(interaction.guild.id)
        await interaction.response.send_message(f"🗑️ `{word}` kelimesi karalisteden kaldırıldı.", ephemeral=True)
    else:
        await interaction.response.send_message("Bu kelime karalistede değil.", ephemeral=True)

@blacklist_group.command(name="list", description="Sunucudaki tüm yasaklı kelimeleri listeler.")
@app_commands.checks.has_permissions(administrator=True)
async def list_blacklist(interaction: discord.Interaction):
    words = blacklist_cache.get(interaction.guild.id)
    if not words:
        await interaction.response.send_message("Sunucuda karalisteye alınmış kelime bulunmuyor.", ephemeral=True)
        return
    word_list = ", ".join(f"`{w}`" for w in sorted(list(words)))
    await interaction.response.send_message(f"**Karalistedeki Kelimeler:**\n{word_list}", ephemeral=True)


bot.tree.add_command(config_group)
bot.tree.add_command(whitelist_group)
bot.tree.add_command(blacklist_group)

# --- Bot'u Çalıştır ---
load_dotenv()
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
if DISCORD_TOKEN is None:
    print("HATA: DISCORD_TOKEN ortam değişkeni bulunamadı. Lütfen .env dosyanızı veya sunucu ayarlarınızı kontrol edin.")
else:
    bot.run(DISCORD_TOKEN)
